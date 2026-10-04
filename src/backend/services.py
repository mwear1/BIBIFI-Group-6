from database import db
from models import User, Person, Room, GalleryEvent, AuditLog

from database import db
from models import User, Person, Room, GalleryEvent, AuditLog


def get_active_person(person_id):
    """Return an active tracked person or raise an error."""
    person = Person.query.filter_by(
        person_id=person_id,
        is_active=True
    ).first()

    if person is None:
        raise ValueError("Person not found or inactive.")

    return person


def get_active_user(user_id):
    """Return an active application user or raise an error."""
    user = User.query.filter_by(
        user_id=user_id,
        is_active=True
    ).first()

    if user is None:
        raise ValueError("User not found or inactive.")

    return user


def require_event_recorder(user_id):
    """Only Employees and Administrators may record gallery events."""
    user = get_active_user(user_id)

    if user.role.name not in {"Employee", "Administrator"}:
        raise PermissionError(
            "User is not authorized to record gallery events."
        )

    return user

def is_inside_gallery(person_id):
    """Return True if the person's latest gallery event is an entry."""

    last_event = (
        GalleryEvent.query
        .filter(
            GalleryEvent.person_id == person_id,
            GalleryEvent.event_type.in_(
                ["GALLERY_ENTER", "GALLERY_EXIT"]
            )
        )
        .order_by(GalleryEvent.event_id.desc())
        .first()
    )

    if last_event is None:
        return False

    return last_event.event_type == "GALLERY_ENTER"

def get_current_room(person_id):
    """Return the current Room object, or None if not in a room."""

    last_event = (
        GalleryEvent.query
        .filter(
            GalleryEvent.person_id == person_id,
            GalleryEvent.event_type.in_(
                ["ROOM_ENTER", "ROOM_EXIT"]
            )
        )
        .order_by(GalleryEvent.event_id.desc())
        .first()
    )

    if last_event is None:
        return None

    if last_event.event_type == "ROOM_ENTER":
        return last_event.room

    return None

def write_audit_log(
    user_id,
    action,
    target_type,
    target_id,
    result,
    details=None
):
    """Add an audit record to the current transaction."""

    audit = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        result=result,
        details=details
    )

    db.session.add(audit)

def record_gallery_entry(person_id, user_id):
    """Record a valid gallery entry."""

    try:
        person = get_active_person(person_id)
        user = require_event_recorder(user_id)

        # Reject duplicate gallery entry.
        if is_inside_gallery(person.person_id):
            raise ValueError("Person is already inside the gallery.")

        event = GalleryEvent(
            person_id=person.person_id,
            room_id=None,
            user_id=user.user_id,
            event_type="GALLERY_ENTER"
        )

        db.session.add(event)

        # Assign the event ID before creating its audit record.
        db.session.flush()

        write_audit_log(
            user_id=user.user_id,
            action="GALLERY_ENTER",
            target_type="GalleryEvent",
            target_id=event.event_id,
            result="SUCCESS",
            details=f"{person.name} entered the gallery."
        )

        db.session.commit()

        return event

    except Exception:
        # Prevent partial database changes if anything fails.
        db.session.rollback()
        raise

def record_gallery_exit(person_id, user_id):
    """Record a valid gallery exit."""

    try:
        person = get_active_person(person_id)
        user = require_event_recorder(user_id)

        # Cannot leave a gallery the person is not currently inside.
        if not is_inside_gallery(person.person_id):
            raise ValueError("Person is not currently inside the gallery.")

        # Require the person to leave their room before leaving the gallery.
        if get_current_room(person.person_id) is not None:
            raise ValueError(
                "Person must leave their current room before leaving the gallery."
            )

        event = GalleryEvent(
            person_id=person.person_id,
            room_id=None,
            user_id=user.user_id,
            event_type="GALLERY_EXIT"
        )

        db.session.add(event)
        db.session.flush()

        write_audit_log(
            user_id=user.user_id,
            action="GALLERY_EXIT",
            target_type="GalleryEvent",
            target_id=event.event_id,
            result="SUCCESS",
            details=f"{person.name} left the gallery."
        )

        db.session.commit()

        return event

    except Exception:
        db.session.rollback()
        raise

def record_room_entry(person_id, room_id, user_id):
    """Record a valid room entry."""

    try:
        person = get_active_person(person_id)
        user = require_event_recorder(user_id)

        room = Room.query.filter_by(
            room_id=room_id,
            is_active=True
        ).first()

        if room is None:
            raise ValueError("Room not found or inactive.")

        # A person must already be inside the gallery.
        if not is_inside_gallery(person.person_id):
            raise ValueError(
                "Person must enter the gallery before entering a room."
            )

        # A person cannot occupy multiple rooms simultaneously.
        if get_current_room(person.person_id) is not None:
            raise ValueError("Person is already inside a room.")

        event = GalleryEvent(
            person_id=person.person_id,
            room_id=room.room_id,
            user_id=user.user_id,
            event_type="ROOM_ENTER"
        )

        db.session.add(event)
        db.session.flush()

        write_audit_log(
            user_id=user.user_id,
            action="ROOM_ENTER",
            target_type="GalleryEvent",
            target_id=event.event_id,
            result="SUCCESS",
            details=f"{person.name} entered {room.name}."
        )

        db.session.commit()

        return event

    except Exception:
        db.session.rollback()
        raise

def record_room_exit(person_id, room_id, user_id):
    """Record a valid room exit."""

    try:
        person = get_active_person(person_id)
        user = require_event_recorder(user_id)

        room = Room.query.filter_by(
            room_id=room_id,
            is_active=True
        ).first()

        if room is None:
            raise ValueError("Room not found or inactive.")

        current_room = get_current_room(person.person_id)

        # The person must currently occupy the requested room.
        if current_room is None:
            raise ValueError("Person is not currently inside a room.")

        if current_room.room_id != room.room_id:
            raise ValueError(
                "Person cannot leave a room they do not currently occupy."
            )

        event = GalleryEvent(
            person_id=person.person_id,
            room_id=room.room_id,
            user_id=user.user_id,
            event_type="ROOM_EXIT"
        )

        db.session.add(event)
        db.session.flush()

        write_audit_log(
            user_id=user.user_id,
            action="ROOM_EXIT",
            target_type="GalleryEvent",
            target_id=event.event_id,
            result="SUCCESS",
            details=f"{person.name} left {room.name}."
        )

        db.session.commit()

        return event

    except Exception:
        db.session.rollback()
        raise