from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

import app as app_module
from database import db
from models import AuditLog, GalleryEvent, Person, Room, User, UserSession


def login(client, username, password):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def csrf_headers(login_response):
    return {"X-CSRF-Token": login_response.json["csrf_token"]}


def test_admin_edits_reactivates_user_and_password_change_revokes_sessions(api_app):
    application, data = api_app
    admin = application.test_client()
    target = application.test_client()
    admin_login = login(admin, "admin", "Administrator-password-123")
    target_login = login(target, "guest", "Guest-password-123")
    assert admin_login.status_code == target_login.status_code == 200

    user_id = data["users"]["guest"]
    updated = admin.put(
        f"/api/admin/users/{user_id}",
        json={
            "username": "guest-updated",
            "full_name": "Updated Guest",
            "email": "guest-updated@example.test",
            "password": "Updated-Guest-Password-123",
        },
        headers=csrf_headers(admin_login),
    )
    assert updated.status_code == 200
    assert updated.json["user"]["username"] == "guest-updated"
    assert updated.json["user"]["full_name"] == "Updated Guest"
    assert updated.json["user"]["email"] == "guest-updated@example.test"
    assert target.get("/api/auth/me").status_code == 401

    disabled = admin.post(
        f"/api/admin/users/{user_id}/disable",
        headers=csrf_headers(admin_login),
    )
    assert disabled.status_code == 200
    assert disabled.json["user"]["is_active"] is False
    enabled = admin.post(
        f"/api/admin/users/{user_id}/enable",
        headers=csrf_headers(admin_login),
    )
    assert enabled.status_code == 200
    assert enabled.json["user"]["is_active"] is True

    fresh_login = login(
        application.test_client(),
        "guest-updated",
        "Updated-Guest-Password-123",
    )
    assert fresh_login.status_code == 200

    with application.app_context():
        assert AuditLog.query.filter_by(action="USER_UPDATED").count() == 1
        assert AuditLog.query.filter_by(action="USER_DISABLED").count() == 1
        assert AuditLog.query.filter_by(action="USER_ENABLED").count() == 1
        old_session = UserSession.query.filter_by(
            user_id=user_id
        ).order_by(UserSession.session_id.asc()).first()
        assert old_session.revoked_at is not None


def test_admin_edits_disables_and_reactivates_room(api_app):
    application, data = api_app
    admin = application.test_client()
    auth = login(admin, "admin", "Administrator-password-123")
    room_id = data["room_id"]

    updated = admin.put(
        f"/api/admin/rooms/{room_id}",
        json={"name": "Updated Gallery Room", "description": "Updated", "capacity": 12},
        headers=csrf_headers(auth),
    )
    assert updated.status_code == 200
    assert updated.json["room"]["name"] == "Updated Gallery Room"
    assert updated.json["room"]["capacity"] == 12

    disabled = admin.post(
        f"/api/admin/rooms/{room_id}/disable",
        headers=csrf_headers(auth),
    )
    assert disabled.status_code == 200
    assert disabled.json["room"]["is_active"] is False
    all_rooms = admin.get("/api/admin/rooms")
    assert next(room for room in all_rooms.json["rooms"] if room["room_id"] == room_id)["is_active"] is False

    enabled = admin.post(
        f"/api/admin/rooms/{room_id}/enable",
        headers=csrf_headers(auth),
    )
    assert enabled.status_code == 200
    assert enabled.json["room"]["is_active"] is True


def test_admin_cannot_disable_room_while_person_is_inside(api_app):
    application, data = api_app
    employee = application.test_client()
    admin = application.test_client()
    employee_login = login(employee, "employee", "Employee-password-123")
    admin_login = login(admin, "admin", "Administrator-password-123")
    person_id = data["person_id"]
    room_id = data["room_id"]

    gallery_entry = employee.post(
        "/api/events/gallery/entry",
        json={"person_id": person_id},
        headers=csrf_headers(employee_login),
    )
    room_entry = employee.post(
        f"/api/events/rooms/{room_id}/entry",
        json={"person_id": person_id},
        headers=csrf_headers(employee_login),
    )
    assert gallery_entry.status_code == room_entry.status_code == 201

    rejected = admin.post(
        f"/api/admin/rooms/{room_id}/disable",
        headers=csrf_headers(admin_login),
    )
    assert rejected.status_code == 400
    assert "while people are inside" in rejected.json["error"]

    room_exit = employee.post(
        f"/api/events/rooms/{room_id}/exit",
        json={"person_id": person_id},
        headers=csrf_headers(employee_login),
    )
    gallery_exit = employee.post(
        "/api/events/gallery/exit",
        json={"person_id": person_id},
        headers=csrf_headers(employee_login),
    )
    assert room_exit.status_code == gallery_exit.status_code == 201
    accepted = admin.post(
        f"/api/admin/rooms/{room_id}/disable",
        headers=csrf_headers(admin_login),
    )
    assert accepted.status_code == 200


def test_admin_edits_disables_and_reactivates_person(api_app):
    application, data = api_app
    admin = application.test_client()
    auth = login(admin, "admin", "Administrator-password-123")
    person_id = data["person_id"]

    updated = admin.put(
        f"/api/admin/persons/{person_id}",
        json={"name": "Updated Visitor", "identifier": "UPDATED-001"},
        headers=csrf_headers(auth),
    )
    assert updated.status_code == 200
    assert updated.json["person"]["name"] == "Updated Visitor"
    assert updated.json["person"]["identifier"] == "UPDATED-001"

    disabled = admin.post(
        f"/api/admin/persons/{person_id}/disable",
        headers=csrf_headers(auth),
    )
    assert disabled.status_code == 200
    assert disabled.json["person"]["is_active"] is False
    assert not any(
        person["person_id"] == person_id
        for person in admin.get("/api/persons").json["persons"]
    )

    enabled = admin.post(
        f"/api/admin/persons/{person_id}/enable",
        headers=csrf_headers(auth),
    )
    assert enabled.status_code == 200
    assert enabled.json["person"]["is_active"] is True
    assert any(
        person["person_id"] == person_id
        for person in admin.get("/api/persons").json["persons"]
    )


def test_admin_cannot_disable_person_until_gallery_exit(api_app):
    application, data = api_app
    employee = application.test_client()
    admin = application.test_client()
    employee_login = login(employee, "employee", "Employee-password-123")
    admin_login = login(admin, "admin", "Administrator-password-123")
    person_id = data["person_id"]

    entry = employee.post(
        "/api/events/gallery/entry",
        json={"person_id": person_id},
        headers=csrf_headers(employee_login),
    )
    assert entry.status_code == 201
    rejected = admin.post(
        f"/api/admin/persons/{person_id}/disable",
        headers=csrf_headers(admin_login),
    )
    assert rejected.status_code == 400
    assert "exit the gallery" in rejected.json["error"]

    exit_response = employee.post(
        "/api/events/gallery/exit",
        json={"person_id": person_id},
        headers=csrf_headers(employee_login),
    )
    assert exit_response.status_code == 201
    accepted = admin.post(
        f"/api/admin/persons/{person_id}/disable",
        headers=csrf_headers(admin_login),
    )
    assert accepted.status_code == 200


def test_idle_timeout_revokes_and_audits_session(api_app):
    application, data = api_app
    client = application.test_client()
    auth = login(client, "employee", "Employee-password-123")
    assert auth.status_code == 200

    with application.app_context():
        auth_session = UserSession.query.filter_by(
            user_id=data["users"]["employee"]
        ).one()
        auth_session.last_seen_at = (
            datetime.now(timezone.utc).replace(tzinfo=None)
            - app_module.IDLE_SESSION_LENGTH
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


def test_event_date_range_and_pagination_boundaries(api_app):
    application, data = api_app
    timestamps = [
        datetime(2024, 1, 1, 10, 0, 0),
        datetime(2024, 6, 1, 10, 0, 0),
        datetime(2024, 12, 31, 10, 0, 0),
        datetime(2025, 1, 1, 10, 0, 0),
    ]
    with application.app_context():
        for stamp in timestamps:
            db.session.add(GalleryEvent(
                person_id=data["person_id"],
                room_id=None,
                user_id=data["users"]["employee"],
                event_type="GALLERY_ENTER",
                timestamp=stamp,
            ))
        db.session.commit()

    client = application.test_client()
    assert login(client, "employee", "Employee-password-123").status_code == 200
    bounded = "?date_from=2024-01-01&date_to=2024-12-31&limit=1&page="
    first = client.get("/api/events" + bounded + "1")
    second = client.get("/api/events" + bounded + "2")
    third = client.get("/api/events" + bounded + "3")
    assert first.status_code == second.status_code == third.status_code == 200
    assert first.json["page"] == 1 and first.json["has_more"] is True
    assert second.json["page"] == 2 and second.json["has_more"] is True
    assert third.json["page"] == 3 and third.json["has_more"] is False
    assert len(first.json["events"]) == len(second.json["events"]) == len(third.json["events"]) == 1
    assert all(event["timestamp"].startswith("2024-") for page in (first, second, third) for event in page.json["events"])

    max_page = client.get("/api/events?limit=1&page=10000")
    assert max_page.status_code == 200
    assert max_page.json["page"] == 10000
    assert max_page.json["has_more"] is False

    invalid_queries = [
        "?date_from=2024-01-01",
        "?date_from=not-a-date&date_to=2024-12-31",
        "?date_from=2024-12-31&date_to=2024-01-01",
        "?date_from=2024-01-01&date_to=2025-01-01",
        "?page=0",
        "?page=10001",
    ]
    for query in invalid_queries:
        assert client.get("/api/events" + query).status_code == 400



def test_room_entry_is_rejected_when_configured_capacity_is_full(api_app):
    application, data = api_app
    admin = application.test_client()
    employee = application.test_client()
    admin_login = login(admin, "admin", "Administrator-password-123")
    employee_login = login(employee, "employee", "Employee-password-123")
    room_id = data["room_id"]

    configured = admin.put(
        f"/api/admin/rooms/{room_id}",
        json={"capacity": 1},
        headers=csrf_headers(admin_login),
    )
    assert configured.status_code == 200

    with application.app_context():
        second_person = Person(name="Second Visitor", identifier="TEST-002")
        db.session.add(second_person)
        db.session.commit()
        second_person_id = second_person.person_id

    first_gallery_entry = employee.post(
        "/api/events/gallery/entry",
        json={"person_id": data["person_id"]},
        headers=csrf_headers(employee_login),
    )
    first_room_entry = employee.post(
        f"/api/events/rooms/{room_id}/entry",
        json={"person_id": data["person_id"]},
        headers=csrf_headers(employee_login),
    )
    second_gallery_entry = employee.post(
        "/api/events/gallery/entry",
        json={"person_id": second_person_id},
        headers=csrf_headers(employee_login),
    )
    rejected_room_entry = employee.post(
        f"/api/events/rooms/{room_id}/entry",
        json={"person_id": second_person_id},
        headers=csrf_headers(employee_login),
    )

    assert first_gallery_entry.status_code == first_room_entry.status_code == 201
    assert second_gallery_entry.status_code == 201
    assert rejected_room_entry.status_code == 400
    assert rejected_room_entry.json["error"] == "Room is at capacity."
    occupancy = employee.get(f"/api/occupancy/rooms/{room_id}")
    assert occupancy.status_code == 200
    assert occupancy.json["count"] == 1
    assert occupancy.json["people"][0]["person_id"] == data["person_id"]


def test_room_capacity_cannot_be_lowered_below_current_occupancy(api_app):
    application, data = api_app
    admin = application.test_client()
    employee = application.test_client()
    admin_login = login(admin, "admin", "Administrator-password-123")
    employee_login = login(employee, "employee", "Employee-password-123")
    room_id = data["room_id"]

    configured = admin.put(
        f"/api/admin/rooms/{room_id}",
        json={"capacity": 3},
        headers=csrf_headers(admin_login),
    )
    assert configured.status_code == 200

    with application.app_context():
        visitors = [
            Person(name=f"Visitor {index}", identifier=f"CAP-{index}")
            for index in (1, 2)
        ]
        db.session.add_all(visitors)
        db.session.commit()
        person_ids = [visitor.person_id for visitor in visitors]

    for person_id in person_ids:
        assert employee.post(
            "/api/events/gallery/entry",
            json={"person_id": person_id},
            headers=csrf_headers(employee_login),
        ).status_code == 201
        assert employee.post(
            f"/api/events/rooms/{room_id}/entry",
            json={"person_id": person_id},
            headers=csrf_headers(employee_login),
        ).status_code == 201

    rejected = admin.put(
        f"/api/admin/rooms/{room_id}",
        json={"capacity": 1},
        headers=csrf_headers(admin_login),
    )
    assert rejected.status_code == 400
    assert "current room occupancy" in rejected.json["error"]

    rooms = admin.get("/api/admin/rooms")
    room = next(item for item in rooms.json["rooms"] if item["room_id"] == room_id)
    assert room["capacity"] == 3


def test_concurrent_room_entries_cannot_exceed_capacity(file_backed_api_app):
    application, data = file_backed_api_app
    with application.app_context():
        room = Room.query.one()
        room.capacity = 1
        second_person = Person(name="Second Visitor", identifier="RACE-002")
        db.session.add(second_person)
        db.session.commit()
        room_id = room.room_id
        person_ids = [data["person_id"], second_person.person_id]

    clients = [application.test_client(), application.test_client()]
    tokens = []
    for client in clients:
        response = login(client, "employee", "Employee-password-123")
        assert response.status_code == 200
        tokens.append(response.json["csrf_token"])

    for client, token, person_id in zip(clients, tokens, person_ids):
        response = client.post(
            "/api/events/gallery/entry",
            json={"person_id": person_id},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 201

    gate = Barrier(2)

    def enter_room(index):
        gate.wait(timeout=5)
        response = clients[index].post(
            f"/api/events/rooms/{room_id}/entry",
            json={"person_id": person_ids[index]},
            headers={"X-CSRF-Token": tokens[index]},
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(enter_room, (0, 1)))

    assert sorted(statuses) == [201, 400]
    with application.app_context():
        room_entries = GalleryEvent.query.filter_by(
            room_id=room_id,
            event_type="ROOM_ENTER",
        ).all()
        assert len(room_entries) == 1
