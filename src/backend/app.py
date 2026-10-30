from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
import math
import os
import secrets

import click
from flask import Flask, g, has_request_context, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from database import db
from models import AuditLog, LoginThrottle, Person, Role, Room, User, UserSession, install_audit_log_triggers
from services import (
    change_user_role,
    create_person,
    create_room,
    create_user,
    disable_user,
    get_event_history,
    get_gallery_occupancy,
    get_person_location,
    get_room_occupancy,
    record_gallery_entry,
    record_gallery_exit,
    record_room_entry,
    record_room_exit,
    update_user,
    set_user_active,
    update_room,
    set_room_active,
    update_person,
    set_person_active,
    write_audit_log,
)

SESSION_LENGTH = timedelta(minutes=30)
IDLE_SESSION_LENGTH = timedelta(minutes=15)
SESSION_TOKEN_KEY = "auth_token"
CSRF_TOKEN_KEY = "csrf_token"
ALLOWED_ROLES = {"Guest", "Employee", "Administrator"}
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW = timedelta(minutes=15)
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BACKEND_DIR, "instance")

app = Flask(
    __name__,
    instance_path=INSTANCE_DIR,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)
APP_ENV = os.environ.get("APP_ENV", "development").lower()
app.config["APP_ENV"] = APP_ENV
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///gallery.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    if APP_ENV == "production":
        raise RuntimeError("FLASK_SECRET_KEY must be set in production.")
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.logger.warning(
        "FLASK_SECRET_KEY is unset; sessions will be invalidated on restart."
    )

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "FLASK_COOKIE_SECURE",
    "1" if APP_ENV == "production" else "0",
).lower() in {"1", "true", "yes"}
if APP_ENV == "production":
    if len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("FLASK_SECRET_KEY must be at least 32 characters in production.")
    if not app.config["SESSION_COOKIE_SECURE"]:
        raise RuntimeError("FLASK_COOKIE_SECURE must be enabled in production.")

app.config["SESSION_COOKIE_PATH"] = "/"
app.config["PERMANENT_SESSION_LIFETIME"] = SESSION_LENGTH
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

db.init_app(app)

with app.app_context():
    db.create_all()
    if db.engine.dialect.name == "sqlite":
        with db.engine.begin() as connection:
            session_columns = {
                row[1] for row in connection.exec_driver_sql("PRAGMA table_info(user_sessions)")
            }
            if "last_seen_at" not in session_columns:
                connection.exec_driver_sql(
                    "ALTER TABLE user_sessions ADD COLUMN last_seen_at DATETIME"
                )
    # Ensure guards are present for existing SQLite databases too.
    with db.engine.begin() as connection:
        install_audit_log_triggers(connection)

    for role_name, description in (
        ("Guest", "Standard authenticated user"),
        ("Employee", "Gallery staff member"),
        ("Administrator", "Privileged application administrator"),
    ):
        if Role.query.filter_by(name=role_name).first() is None:
            db.session.add(Role(name=role_name, description=description))
    db.session.commit()


def _json_error(message, status):
    return jsonify({"error": message}), status


def _json_body():
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _person_json(person):
    return {
        "person_id": person.person_id,
        "name": person.name,
        "identifier": person.identifier,
        "is_active": person.is_active,
    }


def _room_json(room):
    if room is None:
        return None
    return {
        "room_id": room.room_id,
        "name": room.name,
        "description": room.description,
        "capacity": room.capacity,
        "is_active": room.is_active,
    }


def _user_json(user, include_contact=False):
    data = {
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role.name,
        "is_active": user.is_active,
    }
    if include_contact:
        data["full_name"] = user.full_name
        data["email"] = user.email
    return data


def _event_json(event):
    return {
        "event_id": event.event_id,
        "person": _person_json(event.person),
        "room": _room_json(event.room),
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "recorded_by": event.user.username if event.user else None,
    }


def _audit(action, result, user_id=None, details=None):
    db.session.add(AuditLog(
        user_id=user_id,
        action=action,
        target_type="User",
        target_id=user_id,
        result=result,
        details=details,
    ))
    if result == "FAILURE" and has_request_context():
        g.security_failure_audited = True


@app.after_request
def apply_security_controls(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; script-src 'self'; "
        "style-src 'self'; connect-src 'self'",
    )
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )
    # Prevent caching of API responses and authenticated pages.
    if (
        request.path.startswith("/api/")
        or getattr(g, "current_user", None) is not None
    ):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    if app.config["APP_ENV"] == "production":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")

    if (
        response.status_code in {400, 401, 403, 413, 429}
        and not getattr(g, "security_failure_audited", False)
    ):
        actor = getattr(g, "current_user", None)
        _audit(
            "REQUEST_REJECTED",
            "FAILURE",
            user_id=actor.user_id if actor is not None else None,
            details=(
                f"Rejected HTTP {response.status_code} request to "
                f"{request.endpoint or request.path}."
            ),
        )
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not persist request rejection audit.")
    auth_session = getattr(g, "auth_session", None)
    if (
        response.status_code < 400
        and auth_session is not None
        and auth_session.revoked_at is None
    ):
        auth_session.last_seen_at = _utc_now()
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not refresh authenticated session activity.")
    return response


def _login_ip_hash():
    secret = app.config["SECRET_KEY"]
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    address = (request.remote_addr or "unknown").encode("utf-8")
    return hmac.new(secret, address, hashlib.sha256).hexdigest()


def _login_blocked_response(ip_hash):
    record = LoginThrottle.query.filter_by(ip_hash=ip_hash).first()
    now = _utc_now()
    if record is None or record.blocked_until is None or record.blocked_until <= now:
        return None

    g.security_failure_audited = True
    retry_after = max(1, math.ceil((record.blocked_until - now).total_seconds()))
    response = _json_error("Too many login attempts. Try again later.", 429)
    response[0].headers["Retry-After"] = str(retry_after)
    return response


def _record_login_failure(ip_hash, user_id=None):
    now = _utc_now()
    record = LoginThrottle.query.filter_by(ip_hash=ip_hash).first()
    if record is None:
        record = LoginThrottle(
            ip_hash=ip_hash,
            window_started_at=now,
            failure_count=0,
        )
        db.session.add(record)
    elif record.window_started_at + LOGIN_FAILURE_WINDOW <= now:
        record.window_started_at = now
        record.failure_count = 0
        record.blocked_until = None

    record.failure_count += 1
    if record.failure_count >= LOGIN_FAILURE_LIMIT:
        record.blocked_until = now + LOGIN_FAILURE_WINDOW
    _audit(
        "LOGIN_FAILED",
        "FAILURE",
        user_id=user_id,
        details="Invalid credentials or malformed login request.",
    )
    if record.failure_count == LOGIN_FAILURE_LIMIT:
        _audit(
            "LOGIN_RATE_LIMIT_TRIGGERED",
            "FAILURE",
            user_id=None,
            details="Login failure threshold reached for a client address.",
        )
    db.session.commit()


@app.before_request
def load_authenticated_user():
    g.current_user = None
    g.auth_session = None

    raw_token = session.get(SESSION_TOKEN_KEY)
    if not isinstance(raw_token, str):
        return None

    auth_session = UserSession.query.filter_by(
        token_hash=_token_digest(raw_token),
        revoked_at=None,
    ).first()

    if auth_session is None:
        session.clear()
        return None

    now = _utc_now()
    last_activity = auth_session.last_seen_at or auth_session.created_at
    idle_expired = (
        last_activity is not None
        and last_activity + IDLE_SESSION_LENGTH <= now
    )
    if (
        auth_session.expires_at <= now
        or idle_expired
        or not auth_session.user.is_active
        or not auth_session.user.role.is_active
    ):
        auth_session.revoked_at = _utc_now()
        _audit(
            "SESSION_REJECTED",
            "FAILURE",
            user_id=auth_session.user_id,
            details=(
                "Idle/absolute-expired or inactive session was rejected."
            ),
        )
        db.session.commit()
        session.clear()
        return None

    g.auth_session = auth_session
    g.current_user = auth_session.user

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get(CSRF_TOKEN_KEY)
        supplied = request.headers.get("X-CSRF-Token", "")
        if (
            not isinstance(expected, str)
            or not supplied
            or not hmac.compare_digest(expected, supplied)
        ):
            _audit(
                "CSRF_VALIDATION_FAILED",
                "FAILURE",
                user_id=g.current_user.user_id,
                details=f"Rejected state-changing request to {request.endpoint}.",
            )
            db.session.commit()
            return _json_error("A valid CSRF token is required.", 403)

    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            _audit(
                "AUTHENTICATION_REQUIRED",
                "FAILURE",
                details=f"Unauthenticated request to {request.endpoint}.",
            )
            db.session.commit()
            return _json_error("Authentication is required.", 401)
        return view(*args, **kwargs)
    return wrapped


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.current_user.role.name not in allowed_roles:
                _audit(
                    "ACCESS_DENIED",
                    "FAILURE",
                    user_id=g.current_user.user_id,
                    details=(
                        f"Role {g.current_user.role.name} denied "
                        f"for {request.endpoint}."
                    ),
                )
                db.session.commit()
                return _json_error(
                    "You are not authorized to perform this action.", 403
                )
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _service_response(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except PermissionError as error:
        db.session.rollback()
        actor = getattr(g, "current_user", None)
        _audit(
            "SERVICE_ACCESS_DENIED",
            "FAILURE",
            user_id=actor.user_id if actor is not None else None,
            details=f"Operation {operation.__name__} was denied.",
        )
        db.session.commit()
        return _json_error(str(error), 403)
    except ValueError as error:
        db.session.rollback()
        actor = getattr(g, "current_user", None)
        _audit(
            "SERVICE_REQUEST_REJECTED",
            "FAILURE",
            user_id=actor.user_id if actor is not None else None,
            details=f"Operation {operation.__name__} rejected input or state.",
        )
        db.session.commit()
        return _json_error(str(error), 400)


def _page_user_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.current_user is None:
                return redirect(url_for("login_page", next=request.path))
            if allowed_roles and g.current_user.role.name not in allowed_roles:
                _audit(
                    "ACCESS_DENIED",
                    "FAILURE",
                    user_id=g.current_user.user_id,
                    details=f"Role denied for page {request.endpoint}.",
                )
                db.session.commit()
                return redirect(url_for("dashboard_page"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.get("/")
def home():
    if g.current_user is not None:
        return redirect(url_for("dashboard_page"))
    return redirect(url_for("login_page"))


@app.get("/login")
def login_page():
    if g.current_user is not None:
        return redirect(url_for("dashboard_page"))
    return render_template("login.html")


@app.get("/dashboard")
@_page_user_required()
def dashboard_page():
    return render_template("dashboard.html", current_user=g.current_user)


@app.get("/events")
@_page_user_required("Employee", "Administrator")
def events_page():
    return render_template("events.html", current_user=g.current_user)


@app.get("/admin")
@_page_user_required("Administrator")
def admin_page():
    return render_template("admin.html", current_user=g.current_user)


@app.get("/healthz")
def health_check():
    return jsonify({"service": "Secure Gallery Access Tracker", "status": "ok"})


@app.post("/api/auth/login")
def login():
    ip_hash = _login_ip_hash()
    blocked_response = _login_blocked_response(ip_hash)
    if blocked_response is not None:
        return blocked_response

    body = _json_body()
    if body is None:
        _record_login_failure(ip_hash)
        return _json_error("A JSON object is required.", 400)

    username = body.get("username")
    password = body.get("password")
    if (
        not isinstance(username, str)
        or not username
        or len(username) > 80
        or not isinstance(password, str)
        or not password
        or len(password) > 1024
    ):
        _record_login_failure(ip_hash)
        return _json_error("Username or password is invalid.", 401)

    user = User.query.filter_by(username=username).first()
    password_matches = (
        user.check_password(password)
        if user is not None
        else check_password_hash(DUMMY_PASSWORD_HASH, password)
    )
    valid_user = (
        user is not None
        and user.is_active
        and user.role.is_active
        and password_matches
    )

    if not valid_user:
        _record_login_failure(
            ip_hash,
            user_id=user.user_id if user is not None else None,
        )
        return _json_error("Username or password is invalid.", 401)

    LoginThrottle.query.filter_by(ip_hash=ip_hash).delete(
        synchronize_session=False
    )
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = _utc_now()
    auth_session = UserSession(
        token_hash=_token_digest(raw_token),
        user_id=user.user_id,
        expires_at=now + SESSION_LENGTH,
        last_seen_at=now,
    )
    db.session.add(auth_session)
    _audit("LOGIN_SUCCEEDED", "SUCCESS", user_id=user.user_id)
    db.session.commit()

    session.clear()
    session.permanent = True
    session[SESSION_TOKEN_KEY] = raw_token
    session[CSRF_TOKEN_KEY] = csrf_token

    response = jsonify({
        "user": _user_json(user, include_contact=True),
        "csrf_token": csrf_token,
        "expires_at": auth_session.expires_at.isoformat() + "Z",
        "idle_expires_at": (now + IDLE_SESSION_LENGTH).isoformat() + "Z",
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/auth/logout")
@login_required
def logout():
    g.auth_session.revoked_at = _utc_now()
    _audit("LOGOUT", "SUCCESS", user_id=g.current_user.user_id)
    db.session.commit()
    session.clear()
    response = jsonify({"message": "Logged out."})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/auth/me")
@login_required
def current_account():
    response = jsonify({
        "user": _user_json(g.current_user, include_contact=True)
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/persons")
@roles_required("Employee", "Administrator")
def active_persons():
    people = Person.query.filter_by(is_active=True).order_by(Person.name).all()
    return jsonify({"persons": [_person_json(person) for person in people]})


@app.get("/api/rooms")
@roles_required("Employee", "Administrator")
def active_rooms():
    rooms = Room.query.filter_by(is_active=True).order_by(Room.name).all()
    return jsonify({"rooms": [_room_json(room) for room in rooms]})


@app.get("/api/occupancy/rooms")
@roles_required("Employee", "Administrator")
def room_occupancy_summary():
    rooms = Room.query.filter_by(is_active=True).order_by(Room.name).all()
    summary = []
    for room in rooms:
        people = get_room_occupancy(room.room_id)
        summary.append({
            "room": _room_json(room),
            "count": len(people),
            "people": [_person_json(person) for person in people],
        })
    return jsonify({"rooms": summary})


@app.get("/api/occupancy/gallery")
@roles_required("Employee", "Administrator")
def gallery_occupancy():
    people = get_gallery_occupancy()
    return jsonify({
        "count": len(people),
        "people": [_person_json(person) for person in people],
    })


@app.get("/api/occupancy/rooms/<int:room_id>")
@roles_required("Employee", "Administrator")
def room_occupancy(room_id):
    result = _service_response(get_room_occupancy, room_id)
    if isinstance(result, tuple):
        return result
    return jsonify({
        "count": len(result),
        "people": [_person_json(person) for person in result],
    })


@app.get("/api/persons/<int:person_id>/location")
@roles_required("Employee", "Administrator")
def person_location(person_id):
    result = _service_response(get_person_location, person_id)
    if isinstance(result, tuple):
        return result
    return jsonify({
        "status": result["status"],
        "room": _room_json(result["room"]),
    })


@app.get("/api/events")
@roles_required("Employee", "Administrator")
def event_history():
    filters = {}
    for parameter in ("person_id", "room_id", "limit", "page"):
        raw_value = request.args.get(parameter)
        if raw_value is not None:
            try:
                filters[parameter] = int(raw_value)
            except ValueError:
                return _json_error(f"{parameter} must be an integer.", 400)

    result = _service_response(
        get_event_history,
        person_id=filters.get("person_id"),
        room_id=filters.get("room_id"),
        event_type=request.args.get("event_type"),
        limit=filters.get("limit", 100),
        page=filters.get("page", 1),
        date_from=request.args.get("date_from"),
        date_to=request.args.get("date_to"),
    )
    if isinstance(result, tuple):
        return result
    limit = filters.get("limit", 100)
    page = filters.get("page", 1)
    has_more = False
    if len(result) == limit and page < 10000:
        next_page = _service_response(
            get_event_history,
            person_id=filters.get("person_id"),
            room_id=filters.get("room_id"),
            event_type=request.args.get("event_type"),
            limit=limit,
            page=page + 1,
            date_from=request.args.get("date_from"),
            date_to=request.args.get("date_to"),
        )
        has_more = bool(next_page) if not isinstance(next_page, tuple) else False
    return jsonify({
        "events": [_event_json(event) for event in result],
        "page": page,
        "limit": limit,
        "has_more": has_more,
    })


def _record_event(operation, person_id, room_id=None):
    if type(person_id) is not int or person_id <= 0:
        return _json_error("person_id must be a positive integer.", 400)
    if room_id is not None and (type(room_id) is not int or room_id <= 0):
        return _json_error("room_id must be a positive integer.", 400)

    args = [person_id]
    if room_id is not None:
        args.append(room_id)
    args.append(g.current_user.user_id)

    event = _service_response(operation, *args)
    if isinstance(event, tuple):
        return event
    return jsonify({"event": _event_json(event)}), 201


@app.post("/api/events/gallery/entry")
@roles_required("Employee", "Administrator")
def gallery_entry():
    body = _json_body()
    if body is None:
        return _json_error("A JSON object is required.", 400)
    return _record_event(record_gallery_entry, body.get("person_id"))


@app.post("/api/events/gallery/exit")
@roles_required("Employee", "Administrator")
def gallery_exit():
    body = _json_body()
    if body is None:
        return _json_error("A JSON object is required.", 400)
    return _record_event(record_gallery_exit, body.get("person_id"))


@app.post("/api/events/rooms/<int:room_id>/entry")
@roles_required("Employee", "Administrator")
def room_entry(room_id):
    body = _json_body()
    if body is None:
        return _json_error("A JSON object is required.", 400)
    return _record_event(record_room_entry, body.get("person_id"), room_id)


@app.post("/api/events/rooms/<int:room_id>/exit")
@roles_required("Employee", "Administrator")
def room_exit(room_id):
    body = _json_body()
    if body is None:
        return _json_error("A JSON object is required.", 400)
    return _record_event(record_room_exit, body.get("person_id"), room_id)


@app.get("/api/admin/users")
@roles_required("Administrator")
def admin_list_users():
    users = User.query.order_by(User.username).all()
    return jsonify({"users": [_user_json(user, include_contact=True) for user in users]})


@app.post("/api/admin/users")
@roles_required("Administrator")
def admin_create_user():
    body = _json_body()
    if body is None:
        return _json_error("A JSON object is required.", 400)

    username = body.get("username")
    password = body.get("password")
    role_name = body.get("role")
    full_name = body.get("full_name")
    email = body.get("email")

    if not isinstance(username, str) or not username.strip() or len(username) > 80:
        return _json_error("username must contain 1 to 80 characters.", 400)
    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        return _json_error("password must contain 12 to 1024 characters.", 400)
    if not isinstance(role_name, str) or role_name not in ALLOWED_ROLES:
        return _json_error("role must be Guest, Employee, or Administrator.", 400)
    if full_name is not None and (
        not isinstance(full_name, str) or len(full_name) > 100
    ):
        return _json_error("full_name must be at most 100 characters.", 400)
    if email is not None and (
        not isinstance(email, str) or len(email) > 120
    ):
        return _json_error("email must be at most 120 characters.", 400)

    user = _service_response(
        create_user,
        username.strip(),
        password,
        role_name,
        g.current_user.user_id,
        full_name=full_name,
        email=email or None,
    )
    if isinstance(user, tuple):
        return user
    return jsonify({"user": _user_json(user, include_contact=True)}), 201


@app.put("/api/admin/users/<int:user_id>")
@roles_required("Administrator")
def admin_update_user(user_id):
    body = _json_body()
    allowed = {"username", "full_name", "email", "password"}
    if body is None or not body or set(body) - allowed:
        return _json_error("Provide valid account fields to update.", 400)
    if "username" in body and (
        not isinstance(body["username"], str)
        or not body["username"].strip()
        or len(body["username"]) > 80
    ):
        return _json_error("username must contain 1 to 80 characters.", 400)
    if "full_name" in body and body["full_name"] is not None and (
        not isinstance(body["full_name"], str) or len(body["full_name"]) > 100
    ):
        return _json_error("full_name must be at most 100 characters.", 400)
    if "email" in body and body["email"] is not None and (
        not isinstance(body["email"], str) or len(body["email"]) > 120
    ):
        return _json_error("email must be at most 120 characters.", 400)
    if "password" in body and (
        not isinstance(body["password"], str)
        or not 12 <= len(body["password"]) <= 1024
    ):
        return _json_error("password must contain 12 to 1024 characters.", 400)
    changes = dict(body)
    if "username" in changes:
        changes["username"] = changes["username"].strip()
    user = _service_response(
        update_user, user_id, g.current_user.user_id, **changes
    )
    if isinstance(user, tuple):
        return user
    return jsonify({"user": _user_json(user, include_contact=True)})


@app.post("/api/admin/users/<int:user_id>/enable")
@roles_required("Administrator")
def admin_enable_user(user_id):
    user = _service_response(set_user_active, user_id, True, g.current_user.user_id)
    if isinstance(user, tuple):
        return user
    return jsonify({"user": _user_json(user, include_contact=True)})


@app.post("/api/admin/users/<int:user_id>/disable")
@roles_required("Administrator")
def admin_disable_user(user_id):
    user = _service_response(disable_user, user_id, g.current_user.user_id)
    if isinstance(user, tuple):
        return user
    return jsonify({"user": _user_json(user, include_contact=True)})


@app.put("/api/admin/users/<int:user_id>/role")
@roles_required("Administrator")
def admin_change_role(user_id):
    body = _json_body()
    if (
        body is None
        or not isinstance(body.get("role"), str)
        or body["role"] not in ALLOWED_ROLES
    ):
        return _json_error("role must be Guest, Employee, or Administrator.", 400)

    user = _service_response(
        change_user_role, user_id, body["role"], g.current_user.user_id
    )
    if isinstance(user, tuple):
        return user
    return jsonify({"user": _user_json(user, include_contact=True)})


@app.get("/api/admin/audit-logs")
@roles_required("Administrator")
def admin_audit_logs():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        return _json_error("limit must be an integer.", 400)
    if limit < 1 or limit > 500:
        return _json_error("limit must be between 1 and 500.", 400)

    logs = AuditLog.query.order_by(AuditLog.audit_id.desc()).limit(limit).all()
    return jsonify({
        "audit_logs": [
            {
                "audit_id": item.audit_id,
                "user_id": item.user_id,
                "username": item.user.username if item.user else None,
                "action": item.action,
                "target_type": item.target_type,
                "target_id": item.target_id,
                "result": item.result,
                "details": item.details,
                "timestamp": item.timestamp.isoformat() if item.timestamp else None,
            }
            for item in logs
        ]
    })


@app.get("/api/admin/rooms")
@roles_required("Administrator")
def admin_list_rooms():
    rooms = Room.query.order_by(Room.name).all()
    return jsonify({"rooms": [_room_json(room) for room in rooms]})


@app.put("/api/admin/rooms/<int:room_id>")
@roles_required("Administrator")
def admin_update_room(room_id):
    body = _json_body()
    allowed = {"name", "description", "capacity"}
    if body is None or not body or set(body) - allowed:
        return _json_error("Provide valid room fields to update.", 400)
    if "name" in body and (
        not isinstance(body["name"], str) or not body["name"].strip()
        or len(body["name"]) > 100
    ):
        return _json_error("name must contain 1 to 100 characters.", 400)
    if "description" in body and body["description"] is not None and (
        not isinstance(body["description"], str) or len(body["description"]) > 255
    ):
        return _json_error("description must be at most 255 characters.", 400)
    if "capacity" in body and body["capacity"] is not None and (
        type(body["capacity"]) is not int or body["capacity"] < 1
    ):
        return _json_error("capacity must be a positive integer or null.", 400)
    changes = dict(body)
    if "name" in changes:
        changes["name"] = changes["name"].strip()
    room = _service_response(update_room, room_id, g.current_user.user_id, **changes)
    if isinstance(room, tuple):
        return room
    return jsonify({"room": _room_json(room)})


@app.post("/api/admin/rooms/<int:room_id>/disable")
@roles_required("Administrator")
def admin_disable_room(room_id):
    room = _service_response(set_room_active, room_id, False, g.current_user.user_id)
    if isinstance(room, tuple):
        return room
    return jsonify({"room": _room_json(room)})


@app.post("/api/admin/rooms/<int:room_id>/enable")
@roles_required("Administrator")
def admin_enable_room(room_id):
    room = _service_response(set_room_active, room_id, True, g.current_user.user_id)
    if isinstance(room, tuple):
        return room
    return jsonify({"room": _room_json(room)})


@app.post("/api/admin/rooms")
@roles_required("Administrator")
def admin_create_room():
    body = _json_body()
    if body is None:
        return _json_error("A JSON object is required.", 400)

    name = body.get("name")
    description = body.get("description")
    capacity = body.get("capacity")
    if not isinstance(name, str) or not name.strip() or len(name) > 100:
        return _json_error("name must contain 1 to 100 characters.", 400)
    if description is not None and (
        not isinstance(description, str) or len(description) > 255
    ):
        return _json_error("description must be at most 255 characters.", 400)
    if capacity is not None and (type(capacity) is not int or capacity < 1):
        return _json_error("capacity must be a positive integer.", 400)

    room = _service_response(
        create_room,
        name.strip(),
        g.current_user.user_id,
        description=description,
        capacity=capacity,
    )
    if isinstance(room, tuple):
        return room
    return jsonify({"room": _room_json(room)}), 201


@app.get("/api/admin/persons")
@roles_required("Administrator")
def admin_list_persons():
    people = Person.query.order_by(Person.name).all()
    return jsonify({"persons": [_person_json(person) for person in people]})


@app.put("/api/admin/persons/<int:person_id>")
@roles_required("Administrator")
def admin_update_person(person_id):
    body = _json_body()
    allowed = {"name", "identifier"}
    if body is None or not body or set(body) - allowed:
        return _json_error("Provide valid tracked-person fields to update.", 400)
    for field in ("name", "identifier"):
        if field in body and (
            not isinstance(body[field], str) or not body[field].strip()
            or len(body[field]) > 100
        ):
            return _json_error(f"{field} must contain 1 to 100 characters.", 400)
    changes = {key: value.strip() for key, value in body.items()}
    person = _service_response(
        update_person, person_id, g.current_user.user_id, **changes
    )
    if isinstance(person, tuple):
        return person
    return jsonify({"person": _person_json(person)})


@app.post("/api/admin/persons/<int:person_id>/disable")
@roles_required("Administrator")
def admin_disable_person(person_id):
    person = _service_response(
        set_person_active, person_id, False, g.current_user.user_id
    )
    if isinstance(person, tuple):
        return person
    return jsonify({"person": _person_json(person)})


@app.post("/api/admin/persons/<int:person_id>/enable")
@roles_required("Administrator")
def admin_enable_person(person_id):
    person = _service_response(
        set_person_active, person_id, True, g.current_user.user_id
    )
    if isinstance(person, tuple):
        return person
    return jsonify({"person": _person_json(person)})


@app.post("/api/admin/persons")
@roles_required("Administrator")
def admin_create_person():
    body = _json_body()
    if body is None:
        return _json_error("A JSON object is required.", 400)

    name = body.get("name")
    identifier = body.get("identifier")
    if not isinstance(name, str) or not name.strip() or len(name) > 100:
        return _json_error("name must contain 1 to 100 characters.", 400)
    if (
        not isinstance(identifier, str)
        or not identifier.strip()
        or len(identifier) > 100
    ):
        return _json_error("identifier must contain 1 to 100 characters.", 400)

    person = _service_response(
        create_person,
        name.strip(),
        identifier.strip(),
        g.current_user.user_id,
    )
    if isinstance(person, tuple):
        return person
    return jsonify({"person": _person_json(person)}), 201


@app.cli.command("create-admin")
def create_admin_command():
    """Create the first active administrator in an initialized database."""
    existing_admin = User.query.join(Role).filter(
        Role.name == "Administrator",
        User.is_active.is_(True),
    ).first()
    if existing_admin is not None:
        raise click.ClickException("An active administrator already exists.")

    username = click.prompt("Administrator username").strip()
    if not username or len(username) > 80:
        raise click.ClickException("Username must contain 1 to 80 characters.")
    if User.query.filter_by(username=username).first() is not None:
        raise click.ClickException("That username already exists.")

    password = click.prompt(
        "Administrator password",
        hide_input=True,
        confirmation_prompt=True,
    )
    if len(password) < 12 or len(password) > 1024:
        raise click.ClickException("Password must contain 12 to 1024 characters.")

    role = Role.query.filter_by(name="Administrator").first()
    if role is None:
        role = Role(
            name="Administrator",
            description="Privileged administrator",
        )
        db.session.add(role)
        db.session.flush()
    elif not role.is_active:
        role.is_active = True

    user = User(username=username, role_id=role.role_id)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    write_audit_log(
        user_id=None,
        action="ADMIN_BOOTSTRAPPED",
        target_type="User",
        target_id=user.user_id,
        result="SUCCESS",
        details="Initial administrator account provisioned from the local CLI.",
    )
    db.session.commit()
    click.echo(f"Administrator account '{username}' created.")


@app.errorhandler(HTTPException)
def handle_http_error(error):
    if request.path.startswith("/api/"):
        return _json_error(error.description, error.code or 500)
    return error


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    db.session.rollback()
    if isinstance(error, HTTPException):
        return handle_http_error(error)
    app.logger.exception("Unhandled application error")
    if request.path.startswith("/api/"):
        return _json_error("An internal server error occurred.", 500)
    return "An internal server error occurred.", 500


if __name__ == "__main__":
    app.run(debug=False)