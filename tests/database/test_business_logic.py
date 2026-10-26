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
    record_room_exit
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
            person,
            room_one,
            room_two
        ])

        db.session.commit()

        return {
            "guest": guest_user.user_id,
            "employee": employee_user.user_id,
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