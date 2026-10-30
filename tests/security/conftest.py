import os
import sys
from pathlib import Path

import pytest


os.environ["DATABASE_URL"] = "sqlite:///:memory:"
BACKEND_PATH = Path(__file__).resolve().parents[2] / "src" / "backend"
sys.path.insert(0, str(BACKEND_PATH))

from app import app as flask_app
from database import db
from models import Person, Role, Room, User


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


@pytest.fixture
def file_backed_api_app(api_app, tmp_path):
    """Use file-backed SQLite to exercise actual cross-connection locking."""
    application, _ = api_app
    original_uri = application.config["SQLALCHEMY_DATABASE_URI"]
    from sqlalchemy import create_engine

    with application.app_context():
        db.session.remove()
        previous = db.engines[None]
        previous.dispose()
        database_path = (tmp_path / "movement-race.sqlite").as_posix()
        application.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database_path}"
        file_engine = create_engine(
            application.config["SQLALCHEMY_DATABASE_URI"],
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        db.engines[None] = file_engine
        db.create_all()
        roles = {name: Role(name=name, description=name)
                 for name in ("Guest", "Employee", "Administrator")}
        db.session.add_all(roles.values())
        db.session.flush()
        employee = User(username="employee", role_id=roles["Employee"].role_id)
        employee.set_password("Employee-password-123")
        person = Person(name="Concurrent Visitor", identifier="CONCURRENT-001")
        db.session.add_all([employee, person, Room(name="Concurrency Test Room")])
        db.session.commit()
        data = {"person_id": person.person_id}

    yield application, data

    with application.app_context():
        db.session.remove()
        current = db.engines[None]
        current.dispose()
        application.config["SQLALCHEMY_DATABASE_URI"] = original_uri
        db.engines[None] = create_engine(
            original_uri,
            connect_args={"check_same_thread": False},
        )
