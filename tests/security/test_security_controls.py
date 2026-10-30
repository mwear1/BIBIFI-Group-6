import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import app as app_module
from database import db
from models import AuditLog, GalleryEvent, LoginThrottle, Room, User, UserSession


def login(client, username, password):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def test_login_throttle_blocks_repeated_failures_and_audits(api_app):
    application, _ = api_app
    client = application.test_client()

    for _ in range(5):
        response = login(client, "missing-user", "incorrect-password")
        assert response.status_code == 401

    blocked = login(client, "missing-user", "incorrect-password")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    assert blocked.json == {"error": "Too many login attempts. Try again later."}

    with application.app_context():
        throttle = LoginThrottle.query.one()
        assert throttle.failure_count == 5
        assert throttle.ip_hash != "127.0.0.1"
        actions = [item.action for item in AuditLog.query.all()]
        assert actions.count("LOGIN_FAILED") == 5
        assert actions.count("LOGIN_RATE_LIMIT_TRIGGERED") == 1


def test_security_headers_and_sensitive_api_cache_policy(api_app):
    application, _ = api_app
    client = application.test_client()

    page = client.get("/login")
    assert page.headers["X-Content-Type-Options"] == "nosniff"
    assert page.headers["X-Frame-Options"] == "DENY"
    assert page.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    csp = page.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp

    api_response = client.get("/api/auth/me")
    assert api_response.status_code == 401
    assert api_response.headers["Cache-Control"] == "no-store"
    assert api_response.headers["Pragma"] == "no-cache"


def test_xss_payload_is_escaped_in_html_and_inserted_as_text(api_app):
    application, _ = api_app
    payload = '<img src=x onerror=alert(1)>'

    with application.app_context():
        user = User.query.filter_by(username="employee").one()
        user.username = payload
        db.session.commit()

    client = application.test_client()
    assert login(client, payload, "Employee-password-123").status_code == 200
    dashboard = client.get("/dashboard").get_data(as_text=True)
    assert "<img src=x" not in dashboard
    assert "&lt;img src=x onerror=alert(1)&gt;" in dashboard

    javascript = client.get("/static/app.js").get_data(as_text=True)
    assert "textContent" in javascript
    assert "innerHTML" not in javascript


def test_role_and_identifier_substitution_do_not_grant_admin_access(api_app):
    application, data = api_app
    guest = application.test_client()
    guest_login = login(guest, "guest", "Guest-password-123")
    assert guest_login.status_code == 200

    assert guest.get("/api/occupancy/gallery").status_code == 403
    assert guest.get("/api/events?person_id=1").status_code == 403
    assert guest.get("/api/admin/users").status_code == 403

    employee = application.test_client()
    employee_login = login(employee, "employee", "Employee-password-123")
    assert employee_login.status_code == 200
    role_change = employee.put(
        f"/api/admin/users/{data['users']['admin']}/role",
        json={"role": "Administrator"},
        headers={"X-CSRF-Token": employee_login.json["csrf_token"]},
    )
    assert role_change.status_code == 403

    with application.app_context():
        admin = db.session.get(User, data["users"]["admin"])
        assert admin.role.name == "Administrator"
        assert AuditLog.query.filter_by(action="ACCESS_DENIED").count() >= 4


def test_admin_user_creation_ignores_privilege_fields_from_request(api_app):
    application, data = api_app
    admin = application.test_client()
    auth = login(admin, "admin", "Administrator-password-123")
    assert auth.status_code == 200

    response = admin.post(
        "/api/admin/users",
        json={
            "username": "limited-user",
            "password": "Limited-user-password-123",
            "role": "Guest",
            "role_id": 3,
            "user_id": data["users"]["admin"],
            "is_active": False,
        },
        headers={"X-CSRF-Token": auth.json["csrf_token"]},
    )
    assert response.status_code == 201
    assert response.json["user"]["role"] == "Guest"
    assert response.json["user"]["is_active"] is True
    assert "password_hash" not in response.json["user"]

    with application.app_context():
        created = User.query.filter_by(username="limited-user").one()
        assert created.role.name == "Guest"
        assert created.is_active is True
        assert created.user_id != data["users"]["admin"]


def test_sql_injection_and_validation_payloads_are_handled_as_data(api_app):
    application, _ = api_app
    anonymous = application.test_client()
    injected_login = login(anonymous, "' OR 1=1 --", "anything")
    assert injected_login.status_code == 401
    assert injected_login.json == {"error": "Username or password is invalid."}

    employee = application.test_client()
    auth = login(employee, "employee", "Employee-password-123")
    assert auth.status_code == 200
    injected_filter = employee.get("/api/events?person_id=1%20OR%201=1")
    assert injected_filter.status_code == 400
    assert "SQL" not in injected_filter.get_data(as_text=True)

    oversized = employee.post(
        "/api/events/gallery/entry",
        data="x" * 20000,
        content_type="application/json",
        headers={"X-CSRF-Token": auth.json["csrf_token"]},
    )
    assert oversized.status_code == 413
    assert "Traceback" not in oversized.get_data(as_text=True)
    assert "database" not in oversized.get_data(as_text=True).lower()

    with application.app_context():
        assert User.query.count() == 3
        assert AuditLog.query.filter_by(action="REQUEST_REJECTED").count() >= 2


def test_expired_sessions_are_revoked_and_audited(api_app):
    application, data = api_app
    client = application.test_client()
    auth = login(client, "employee", "Employee-password-123")
    assert auth.status_code == 200

    with application.app_context():
        auth_session = UserSession.query.filter_by(
            user_id=data["users"]["employee"]
        ).one()
        auth_session.expires_at = (
            datetime.now(timezone.utc).replace(tzinfo=None)
            - timedelta(seconds=1)
        )
        db.session.commit()

    response = client.get("/api/auth/me")
    assert response.status_code == 401
    with application.app_context():
        auth_session = UserSession.query.filter_by(
            user_id=data["users"]["employee"]
        ).one()
        assert auth_session.revoked_at is not None
        assert AuditLog.query.filter_by(action="SESSION_REJECTED").count() == 1


def test_unexpected_api_errors_do_not_disclose_internal_details(api_app, monkeypatch):
    application, _ = api_app
    client = application.test_client()
    auth = login(client, "employee", "Employee-password-123")
    assert auth.status_code == 200

    def fail_with_sensitive_details():
        raise RuntimeError("sqlite path C:\\private\\gallery.db; secret=do-not-show")

    monkeypatch.setattr(app_module, "get_gallery_occupancy", fail_with_sensitive_details)
    response = client.get("/api/occupancy/gallery")
    body = response.get_data(as_text=True)
    assert response.status_code == 500
    assert body == '{"error":"An internal server error occurred."}\n'
    assert "private" not in body
    assert "do-not-show" not in body


def test_production_rejects_insecure_cookie_configuration():
    project_root = Path(__file__).resolve().parents[2]
    backend_path = str(project_root / "src" / "backend")
    environment = os.environ.copy()
    environment["APP_ENV"] = "production"
    environment["FLASK_SECRET_KEY"] = "production-test-key-" + ("x" * 48)
    environment["FLASK_COOKIE_SECURE"] = "0"
    environment["DATABASE_URL"] = "sqlite:///:memory:"
    code = f"import sys; sys.path.insert(0, {backend_path!r}); import app"

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "FLASK_COOKIE_SECURE must be enabled in production." in result.stderr


def test_audit_records_are_append_only_in_the_application(api_app):
    import pytest

    application, _ = api_app
    with application.app_context():
        item = AuditLog(
            action="SECURITY_TEST",
            target_type="Test",
            result="SUCCESS",
            details="original",
        )
        db.session.add(item)
        db.session.commit()

        item.details = "tampered"
        with pytest.raises(ValueError, match="cannot be changed or deleted"):
            db.session.commit()
        db.session.rollback()

        persisted = AuditLog.query.filter_by(action="SECURITY_TEST").one()
        assert persisted.details == "original"

        db.session.delete(persisted)
        with pytest.raises(ValueError, match="cannot be changed or deleted"):
            db.session.commit()
        db.session.rollback()
        assert AuditLog.query.filter_by(action="SECURITY_TEST").count() == 1


def test_employee_and_admin_role_matrix_on_protected_read_routes(api_app):
    application, data = api_app
    staff_routes = [
        "/api/persons",
        "/api/rooms",
        "/api/occupancy/gallery",
        "/api/occupancy/rooms",
        f"/api/occupancy/rooms/{data['room_id']}",
        f"/api/persons/{data['person_id']}/location",
        "/api/events",
    ]
    admin_routes = ["/api/admin/users", "/api/admin/audit-logs"]

    guest = application.test_client()
    assert login(guest, "guest", "Guest-password-123").status_code == 200
    for path in staff_routes + admin_routes:
        assert guest.get(path).status_code == 403

    employee = application.test_client()
    assert login(employee, "employee", "Employee-password-123").status_code == 200
    for path in staff_routes:
        assert employee.get(path).status_code == 200
    for path in admin_routes:
        assert employee.get(path).status_code == 403

    admin = application.test_client()
    assert login(admin, "admin", "Administrator-password-123").status_code == 200
    for path in staff_routes + admin_routes:
        assert admin.get(path).status_code == 200


def test_sql_injection_payload_in_room_name_is_stored_as_literal_data(api_app):
    application, _ = api_app
    admin = application.test_client()
    auth = login(admin, "admin", "Administrator-password-123")
    payload = "Gallery'); DROP TABLE users; --"

    response = admin.post(
        "/api/admin/rooms",
        json={"name": payload, "capacity": 4},
        headers={"X-CSRF-Token": auth.json["csrf_token"]},
    )
    assert response.status_code == 201
    assert response.json["room"]["name"] == payload

    with application.app_context():
        assert User.query.count() == 3
        assert Room.query.filter_by(name=payload).one().capacity == 4


def test_concurrent_conflicting_movement_requests_are_serialized(file_backed_api_app):
    application, data = file_backed_api_app
    clients = [application.test_client(), application.test_client()]
    tokens = []
    for client in clients:
        response = login(client, "employee", "Employee-password-123")
        assert response.status_code == 200
        tokens.append(response.json["csrf_token"])

    gate = Barrier(2)
    def enter(index):
        gate.wait(timeout=5)
        response = clients[index].post(
            "/api/events/gallery/entry",
            json={"person_id": data["person_id"]},
            headers={"X-CSRF-Token": tokens[index]},
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(enter, (0, 1)))

    assert sorted(statuses) == [201, 400]
    with application.app_context():
        events = GalleryEvent.query.filter_by(person_id=data["person_id"]).all()
        assert len(events) == 1
        assert events[0].event_type == "GALLERY_ENTER"


def test_audit_log_database_guards_reject_bulk_and_direct_sql(api_app):
    application, _ = api_app
    with application.app_context():
        item = AuditLog(
            action="SECURITY_TEST_DATABASE_GUARD",
            target_type="Test",
            result="SUCCESS",
            details="original",
        )
        db.session.add(item)
        db.session.commit()
        audit_id = item.audit_id

        attempts = (
            lambda: db.session.query(AuditLog).filter_by(audit_id=audit_id)
                .update({AuditLog.details: "bulk-tampered"}),
            lambda: db.session.query(AuditLog).filter_by(audit_id=audit_id).delete(),
            lambda: db.session.execute(
                text("UPDATE audit_logs SET details=:value WHERE audit_id=:id"),
                {"value": "sql-tampered", "id": audit_id},
            ),
            lambda: db.session.execute(
                text("DELETE FROM audit_logs WHERE audit_id=:id"), {"id": audit_id}
            ),
        )
        for attempt in attempts:
            with pytest.raises(IntegrityError):
                attempt()
            db.session.rollback()

        persisted = db.session.get(AuditLog, audit_id)
        assert persisted is not None
        assert persisted.details == "original"
