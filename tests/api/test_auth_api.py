import sys
from pathlib import Path

import pytest

BACKEND_PATH = Path(__file__).resolve().parents[2] / "src" / "backend"
sys.path.insert(0, str(BACKEND_PATH))

from app import app as flask_app
from database import db
from models import AuditLog, GalleryEvent, Person, Role, Room, User


@pytest.fixture
def api_app():
    flask_app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret-key",
        SESSION_COOKIE_SECURE=False,
    )

    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        roles = {
            name: Role(name=name, description=name)
            for name in ("Guest", "Employee", "Administrator")
        }
        db.session.add_all(roles.values())
        db.session.flush()

        users = {}
        for name, password in (
            ("guest", "Guest-password-123"),
            ("employee", "Employee-password-123"),
            ("admin", "Administrator-password-123"),
        ):
            role_name = {
                "guest": "Guest",
                "employee": "Employee",
                "admin": "Administrator",
            }[name]
            user = User(username=name, role_id=roles[role_name].role_id)
            user.set_password(password)
            users[name] = user

        person = Person(name="Test Visitor", identifier="TEST-001")
        room = Room(name="Test Room")
        db.session.add_all([*users.values(), person, room])
        db.session.commit()

        data = {
            "users": {name: user.user_id for name, user in users.items()},
            "person_id": person.person_id,
            "room_id": room.room_id,
        }

    yield flask_app, data

    with flask_app.app_context():
        db.session.remove()
        db.drop_all()


def login(client, username, password):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def test_login_returns_account_csrf_token_and_secure_cookie_flags(api_app):
    application, _ = api_app
    client = application.test_client()

    response = login(client, "employee", "Employee-password-123")

    assert response.status_code == 200
    assert response.json["user"]["username"] == "employee"
    assert response.json["user"]["role"] == "Employee"
    assert response.json["csrf_token"]
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie

    account_response = client.get("/api/auth/me")
    assert account_response.status_code == 200
    assert account_response.json["user"]["username"] == "employee"


def test_invalid_login_uses_generic_error_and_writes_failure_audit(api_app):
    application, _ = api_app
    client = application.test_client()

    response = login(client, "missing-user", "incorrect-password")

    assert response.status_code == 401
    assert response.json == {"error": "Username or password is invalid."}
    with application.app_context():
        audit = AuditLog.query.filter_by(action="LOGIN_FAILED").one()
        assert audit.result == "FAILURE"
        assert "password" not in (audit.details or "").lower()


def test_protected_endpoint_requires_login_and_guest_role_is_denied(api_app):
    application, _ = api_app
    anonymous = application.test_client()
    assert anonymous.get("/api/auth/me").status_code == 401
    assert anonymous.get("/api/occupancy/gallery").status_code == 401

    guest = application.test_client()
    response = login(guest, "guest", "Guest-password-123")
    assert response.status_code == 200
    denied = guest.get("/api/occupancy/gallery")
    assert denied.status_code == 403


def test_mutating_request_requires_csrf_and_uses_logged_in_actor(api_app):
    application, data = api_app
    client = application.test_client()
    login_response = login(client, "employee", "Employee-password-123")
    assert login_response.status_code == 200

    payload = {"person_id": data["person_id"], "user_id": data["users"]["admin"]}
    missing_csrf = client.post("/api/events/gallery/entry", json=payload)
    assert missing_csrf.status_code == 403

    response = client.post(
        "/api/events/gallery/entry",
        json=payload,
        headers={"X-CSRF-Token": login_response.json["csrf_token"]},
    )
    assert response.status_code == 201

    with application.app_context():
        event = GalleryEvent.query.one()
        assert event.user_id == data["users"]["employee"]
        assert event.user_id != data["users"]["admin"]


def test_logout_revokes_the_session_even_if_old_cookie_is_replayed(api_app):
    application, _ = api_app
    client = application.test_client()
    login_response = login(client, "employee", "Employee-password-123")
    assert login_response.status_code == 200
    old_cookie = client.get_cookie("session")

    logout_response = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": login_response.json["csrf_token"]},
    )
    assert logout_response.status_code == 200
    assert client.get("/api/auth/me").status_code == 401

    replay_client = application.test_client()
    replay_client.set_cookie("session", old_cookie.value)
    assert replay_client.get("/api/auth/me").status_code == 401


def test_role_change_revokes_target_users_sessions(api_app):
    application, _ = api_app
    admin_client = application.test_client()
    target_client = application.test_client()

    admin_login = login(admin_client, "admin", "Administrator-password-123")
    target_login = login(target_client, "employee", "Employee-password-123")
    assert admin_login.status_code == target_login.status_code == 200
    assert target_client.get("/api/auth/me").status_code == 200

    response = admin_client.put(
        f"/api/admin/users/{target_login.json['user']['user_id']}/role",
        json={"role": "Guest"},
        headers={"X-CSRF-Token": admin_login.json["csrf_token"]},
    )
    assert response.status_code == 200
    assert response.json["user"]["role"] == "Guest"
    assert target_client.get("/api/auth/me").status_code == 401


def test_disabling_user_revokes_target_users_sessions(api_app):
    application, _ = api_app
    admin_client = application.test_client()
    target_client = application.test_client()

    admin_login = login(admin_client, "admin", "Administrator-password-123")
    target_login = login(target_client, "employee", "Employee-password-123")
    assert admin_login.status_code == target_login.status_code == 200

    response = admin_client.post(
        f"/api/admin/users/{target_login.json['user']['user_id']}/disable",
        headers={"X-CSRF-Token": admin_login.json["csrf_token"]},
    )
    assert response.status_code == 200
    assert response.json["user"]["is_active"] is False
    assert target_client.get("/api/auth/me").status_code == 401


def test_guest_cannot_record_events_even_with_a_valid_csrf_token(api_app):
    application, data = api_app
    client = application.test_client()
    login_response = login(client, "guest", "Guest-password-123")
    assert login_response.status_code == 200

    response = client.post(
        "/api/events/gallery/entry",
        json={"person_id": data["person_id"]},
        headers={"X-CSRF-Token": login_response.json["csrf_token"]},
    )

    assert response.status_code == 403
    with application.app_context():
        assert GalleryEvent.query.count() == 0


def test_browser_pages_redirect_anonymous_and_enforce_page_roles(api_app):
    application, _ = api_app
    anonymous = application.test_client()
    assert anonymous.get("/").status_code == 302
    assert anonymous.get("/login").status_code == 200
    assert anonymous.get("/dashboard").headers["Location"].endswith("/login?next=/dashboard")

    guest = application.test_client()
    assert login(guest, "guest", "Guest-password-123").status_code == 200
    assert guest.get("/dashboard").status_code == 200
    assert guest.get("/events").status_code == 302
    assert guest.get("/admin").status_code == 302

    admin = application.test_client()
    assert login(admin, "admin", "Administrator-password-123").status_code == 200
    assert admin.get("/events").status_code == 200
    assert admin.get("/admin").status_code == 200


def test_dashboard_data_endpoints_enforce_employee_and_admin_roles(api_app):
    application, data = api_app
    anonymous = application.test_client()
    assert anonymous.get("/api/persons").status_code == 401
    assert anonymous.get("/api/rooms").status_code == 401
    assert anonymous.get("/api/occupancy/rooms").status_code == 401

    guest = application.test_client()
    assert login(guest, "guest", "Guest-password-123").status_code == 200
    assert guest.get("/api/persons").status_code == 403
    assert guest.get("/api/rooms").status_code == 403
    assert guest.get("/api/occupancy/rooms").status_code == 403

    employee = application.test_client()
    assert login(employee, "employee", "Employee-password-123").status_code == 200
    persons = employee.get("/api/persons")
    rooms = employee.get("/api/rooms")
    occupancy = employee.get("/api/occupancy/rooms")
    assert persons.status_code == rooms.status_code == occupancy.status_code == 200
    assert persons.json["persons"][0]["person_id"] == data["person_id"]
    assert rooms.json["rooms"][0]["room_id"] == data["room_id"]
    assert occupancy.json["rooms"][0]["count"] == 0


def test_admin_user_list_is_administrator_only(api_app):
    application, _ = api_app
    employee = application.test_client()
    assert login(employee, "employee", "Employee-password-123").status_code == 200
    assert employee.get("/api/admin/users").status_code == 403

    admin = application.test_client()
    assert login(admin, "admin", "Administrator-password-123").status_code == 200
    response = admin.get("/api/admin/users")
    assert response.status_code == 200
    assert {user["username"] for user in response.json["users"]} == {"guest", "employee", "admin"}

