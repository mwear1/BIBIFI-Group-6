import sys
from pathlib import Path

import pytest
from flask import Flask

# Allow tests to import modules from src/backend.
BACKEND_PATH = Path(__file__).resolve().parents[2] / "src" / "backend"
sys.path.insert(0, str(BACKEND_PATH))

from database import db
from models import Role, User, Person, Room, GalleryEvent, AuditLog
from services import (
    record_gallery_entry,
    record_gallery_exit,
    record_room_entry,
    record_room_exit,
    get_gallery_occupancy,
    get_room_occupancy,
    get_person_location,
    get_event_history,
    create_user,
    disable_user,
    change_user_role,
    create_room,
    create_person
)

@pytest.fixture
def app():
    """Create a fresh in-memory database for each test."""

    app = Flask(__name__)

    # Use temporary SQLite memory so tests cannot alter gallery.db.
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["TESTING"] = True

    db.init_app(app)

    with app.app_context():
        db.create_all()

        yield app

        # Remove all temporary test data after each test.
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_data(app):
    """Create users, roles, persons, and rooms used by tests."""

    with app.app_context():
        guest_role = Role(
            name="Guest",
            description="Standard authenticated user"
        )

        employee_role = Role(
            name="Employee",
            description="Gallery staff member"
        )

        admin_role = Role(
            name="Administrator",
            description="Privileged administrator"
        )

        db.session.add_all([
            guest_role,
            employee_role,
            admin_role
        ])
        db.session.flush()

        guest_user = User(
            username="guest1",
            role_id=guest_role.role_id,
            full_name="Test Guest",
            email="guest@example.com"
        )
        guest_user.set_password("Guest123!")

        employee_user = User(
            username="employee1",
            role_id=employee_role.role_id,
            full_name="Test Employee",
            email="employee@example.com"
        )
        employee_user.set_password("Employee123!")

        admin_user = User(
            username="admin1",
            role_id=admin_role.role_id,
            full_name="Test Administrator",
            email="admin@example.com"
        )
        admin_user.set_password("Admin123!")

        person = Person(
            name="Alice Johnson",
            identifier="GUEST-001"
        )

        room_one = Room(
            name="Modern Art",
            capacity=50
        )

        room_two = Room(
            name="Photography",
            capacity=40
        )

        db.session.add_all([
            guest_user,
            employee_user,
            admin_user,
            person,
            room_one,
            room_two
        ])

        db.session.commit()

        return {
            "guest": guest_user.user_id,
            "employee": employee_user.user_id,
            "admin": admin_user.user_id,
            "person": person.person_id,
            "room_one": room_one.room_id,
            "room_two": room_two.room_id
        }

def test_duplicate_gallery_entry_rejected(app, test_data):
    """A person cannot enter the gallery twice."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        with pytest.raises(
            ValueError,
            match="already inside the gallery"
        ):
            record_gallery_entry(
                test_data["person"],
                test_data["employee"]
            )


def test_gallery_exit_while_outside_rejected(app, test_data):
    """A person cannot leave the gallery while outside."""

    with app.app_context():
        with pytest.raises(
            ValueError,
            match="not currently inside the gallery"
        ):
            record_gallery_exit(
                test_data["person"],
                test_data["employee"]
            )

def test_room_entry_while_outside_rejected(app, test_data):
    """A person must enter the gallery before entering a room."""

    with app.app_context():
        with pytest.raises(
            ValueError,
            match="enter the gallery"
        ):
            record_room_entry(
                test_data["person"],
                test_data["room_one"],
                test_data["employee"]
            )


def test_multiple_room_occupancy_rejected(app, test_data):
    """A person cannot occupy multiple rooms at the same time."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        with pytest.raises(
            ValueError,
            match="already inside a room"
        ):
            record_room_entry(
                test_data["person"],
                test_data["room_two"],
                test_data["employee"]
            )


def test_wrong_room_exit_rejected(app, test_data):
    """A person cannot leave a room they do not currently occupy."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        with pytest.raises(
            ValueError,
            match="do not currently occupy"
        ):
            record_room_exit(
                test_data["person"],
                test_data["room_two"],
                test_data["employee"]
            )


def test_guest_cannot_record_gallery_event(app, test_data):
    """Guest accounts cannot record protected gallery events."""

    with app.app_context():
        with pytest.raises(
            PermissionError,
            match="not authorized"
        ):
            record_gallery_entry(
                test_data["person"],
                test_data["guest"]
            )

def test_valid_gallery_movement_sequence(app, test_data):
    """A valid gallery and room movement sequence should succeed."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        record_room_exit(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        record_gallery_exit(
            test_data["person"],
            test_data["employee"]
        )

        events = GalleryEvent.query.order_by(
            GalleryEvent.event_id
        ).all()

        assert len(events) == 4

def test_valid_event_order(app, test_data):
    """Valid movement events should be stored in the expected order."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        record_room_exit(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        record_gallery_exit(
            test_data["person"],
            test_data["employee"]
        )

        events = GalleryEvent.query.order_by(
            GalleryEvent.event_id
        ).all()

        event_types = [
            event.event_type
            for event in events
        ]

        assert event_types == [
            "GALLERY_ENTER",
            "ROOM_ENTER",
            "ROOM_EXIT",
            "GALLERY_EXIT"
        ]

def test_successful_events_create_audit_logs(app, test_data):
    """Successful gallery events should create matching audit records."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        events = GalleryEvent.query.all()
        audits = AuditLog.query.all()

        assert len(events) == 2
        assert len(audits) == 2

        assert audits[0].action == "GALLERY_ENTER"
        assert audits[0].result == "SUCCESS"

        assert audits[1].action == "ROOM_ENTER"
        assert audits[1].result == "SUCCESS"

def test_database_rejects_invalid_event_type(app, test_data):
    """SQLite should reject unsupported gallery event types."""

    with app.app_context():
        invalid_event = GalleryEvent(
            person_id=test_data["person"],
            user_id=test_data["employee"],
            room_id=None,
            event_type="INVALID_EVENT"
        )

        db.session.add(invalid_event)

        with pytest.raises(Exception):
            db.session.commit()

        # Reset the failed database transaction.
        db.session.rollback()

def test_database_rejects_invalid_audit_result(app, test_data):
    """SQLite should reject unsupported audit result values."""

    with app.app_context():
        invalid_audit = AuditLog(
            user_id=test_data["employee"],
            action="TEST_ACTION",
            target_type="Test",
            target_id=1,
            result="MAYBE",
            details="Invalid audit result test."
        )

        db.session.add(invalid_audit)

        with pytest.raises(Exception):
            db.session.commit()

        db.session.rollback()

def test_gallery_occupancy(app, test_data):
    """Gallery occupancy should include only people currently inside."""

    with app.app_context():
        assert len(get_gallery_occupancy()) == 0

        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        occupants = get_gallery_occupancy()

        assert len(occupants) == 1
        assert occupants[0].person_id == test_data["person"]

        record_gallery_exit(
            test_data["person"],
            test_data["employee"]
        )

        assert len(get_gallery_occupancy()) == 0

def test_room_occupancy(app, test_data):
    """Room occupancy should reflect current room state."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        occupants = get_room_occupancy(
            test_data["room_one"]
        )

        assert len(occupants) == 1
        assert occupants[0].person_id == test_data["person"]

        record_room_exit(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        assert len(
            get_room_occupancy(test_data["room_one"])
        ) == 0

def test_person_location(app, test_data):
    """Person location should change with gallery movement."""

    with app.app_context():
        location = get_person_location(
            test_data["person"]
        )

        assert location["status"] == "OUTSIDE"
        assert location["room"] is None

        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        location = get_person_location(
            test_data["person"]
        )

        assert location["status"] == "IN_GALLERY"

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        location = get_person_location(
            test_data["person"]
        )

        assert location["status"] == "IN_ROOM"
        assert location["room"].room_id == test_data["room_one"]

def test_event_history_filters(app, test_data):
    """Event history should support person and event-type filters."""

    with app.app_context():
        record_gallery_entry(
            test_data["person"],
            test_data["employee"]
        )

        record_room_entry(
            test_data["person"],
            test_data["room_one"],
            test_data["employee"]
        )

        events = get_event_history(
            person_id=test_data["person"]
        )

        assert len(events) == 2

        room_entries = get_event_history(
            person_id=test_data["person"],
            event_type="ROOM_ENTER"
        )

        assert len(room_entries) == 1
        assert room_entries[0].event_type == "ROOM_ENTER"
        assert room_entries[0].room_id == test_data["room_one"]

def test_event_history_rejects_invalid_limit(app, test_data):
    """Historical searches should reject excessive result limits."""

    with app.app_context():
        with pytest.raises(
            ValueError,
            match="between 1 and 500"
        ):
            get_event_history(limit=10000)

def test_admin_can_create_user(app, test_data):
    """Administrators should be able to create secure user accounts."""

    with app.app_context():
        user = create_user(
            username="newemployee",
            password="SecurePass123!",
            role_name="Employee",
            admin_user_id=test_data["admin"],
            full_name="New Employee",
            email="newemployee@example.com"
        )

        assert user.username == "newemployee"
        assert user.role.name == "Employee"
        assert user.password_hash != "SecurePass123!"
        assert user.check_password("SecurePass123!") is True

        audit = AuditLog.query.filter_by(
            action="USER_CREATED"
        ).first()

        assert audit is not None
        assert audit.target_id == user.user_id


def test_employee_cannot_create_user(app, test_data):
    """Employees cannot perform Administrator-only user management."""

    with app.app_context():
        with pytest.raises(
            PermissionError,
            match="Administrator privileges"
        ):
            create_user(
                username="unauthorized",
                password="SecurePass123!",
                role_name="Employee",
                admin_user_id=test_data["employee"]
            )


def test_admin_can_change_user_role(app, test_data):
    """Administrators should be able to change assigned roles."""

    with app.app_context():
        user = change_user_role(
            target_user_id=test_data["guest"],
            new_role_name="Employee",
            admin_user_id=test_data["admin"]
        )

        assert user.role.name == "Employee"

        audit = AuditLog.query.filter_by(
            action="ROLE_CHANGED"
        ).first()

        assert audit is not None
        assert audit.target_id == test_data["guest"]


def test_admin_can_disable_user(app, test_data):
    """Administrators should be able to disable user accounts."""

    with app.app_context():
        user = disable_user(
            target_user_id=test_data["guest"],
            admin_user_id=test_data["admin"]
        )

        assert user.is_active is False

        audit = AuditLog.query.filter_by(
            action="USER_DISABLED"
        ).first()

        assert audit is not None


def test_admin_cannot_disable_self(app, test_data):
    """Administrators should not disable their own account."""

    with app.app_context():
        with pytest.raises(
            ValueError,
            match="cannot disable their own account"
        ):
            disable_user(
                target_user_id=test_data["admin"],
                admin_user_id=test_data["admin"]
            )


def test_admin_can_create_room(app, test_data):
    """Administrators should be able to create gallery rooms."""

    with app.app_context():
        room = create_room(
            name="Sculpture Gallery",
            description="Sculpture exhibits",
            capacity=35,
            admin_user_id=test_data["admin"]
        )

        assert room.name == "Sculpture Gallery"
        assert room.capacity == 35

        audit = AuditLog.query.filter_by(
            action="ROOM_CREATED"
        ).first()

        assert audit is not None


def test_admin_can_create_person(app, test_data):
    """Administrators should be able to create tracked persons."""

    with app.app_context():
        person = create_person(
            name="Bob Smith",
            identifier="GUEST-002",
            admin_user_id=test_data["admin"]
        )

        assert person.name == "Bob Smith"
        assert person.identifier == "GUEST-002"

        audit = AuditLog.query.filter_by(
            action="PERSON_CREATED"
        ).first()

        assert audit is not None