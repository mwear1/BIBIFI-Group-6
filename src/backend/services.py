from database import db
from models import Role, User, Person, Room, GalleryEvent, AuditLog

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

def get_gallery_occupancy():
    """Return all active persons currently inside the gallery."""

    active_people = Person.query.filter_by(is_active=True).all()

    # Only include people whose latest gallery state is inside.
    occupants = [
        person
        for person in active_people
        if is_inside_gallery(person.person_id)
    ]

    return occupants

def get_room_occupancy(room_id):
    """Return all active persons currently occupying a room."""

    room = Room.query.filter_by(
        room_id=room_id,
        is_active=True
    ).first()

    if room is None:
        raise ValueError("Room not found or inactive.")

    active_people = Person.query.filter_by(is_active=True).all()

    occupants = []

    for person in active_people:
        current_room = get_current_room(person.person_id)

        if (
            current_room is not None
            and current_room.room_id == room.room_id
        ):
            occupants.append(person)

    return occupants

def get_person_location(person_id):
    """Return the person's current gallery location."""

    person = get_active_person(person_id)

    if not is_inside_gallery(person.person_id):
        return {
            "status": "OUTSIDE",
            "room": None
        }

    current_room = get_current_room(person.person_id)

    if current_room is None:
        return {
            "status": "IN_GALLERY",
            "room": None
        }

    return {
        "status": "IN_ROOM",
        "room": current_room
    }


def get_event_history(
    person_id=None,
    room_id=None,
    event_type=None,
    limit=100
):
    """Return gallery events using optional search filters."""

    query = GalleryEvent.query

    if person_id is not None:
        query = query.filter(
            GalleryEvent.person_id == person_id
        )

    if room_id is not None:
        query = query.filter(
            GalleryEvent.room_id == room_id
        )

    if event_type is not None:
        if event_type not in {
            "GALLERY_ENTER",
            "GALLERY_EXIT",
            "ROOM_ENTER",
            "ROOM_EXIT"
        }:
            raise ValueError("Invalid event type.")

        query = query.filter(
            GalleryEvent.event_type == event_type
        )

    # Limit large searches to protect database resources.
    if limit < 1 or limit > 500:
        raise ValueError("Limit must be between 1 and 500.")

    return (
        query
        .order_by(GalleryEvent.event_id.desc())
        .limit(limit)
        .all()
    )

def require_admin(user_id):
    """Only active Administrators may perform administrative actions."""

    user = get_active_user(user_id)

    if user.role.name != "Administrator":
        raise PermissionError(
            "Administrator privileges are required."
        )

    return user

def create_user(
    username,
    password,
    role_name,
    admin_user_id,
    full_name=None,
    email=None
):
    """Create a new application user."""

    try:
        admin = require_admin(admin_user_id)

        # Prevent duplicate usernames.
        if User.query.filter_by(username=username).first():
            raise ValueError("Username already exists.")

        # Prevent duplicate email addresses when one is provided.
        if email and User.query.filter_by(email=email).first():
            raise ValueError("Email already exists.")

        role = Role.query.filter_by(
            name=role_name,
            is_active=True
        ).first()

        if role is None:
            raise ValueError("Invalid or inactive role.")

        user = User(
            username=username,
            role_id=role.role_id,
            full_name=full_name,
            email=email
        )

        # Never store the plaintext password.
        user.set_password(password)

        db.session.add(user)
        db.session.flush()

        write_audit_log(
            user_id=admin.user_id,
            action="USER_CREATED",
            target_type="User",
            target_id=user.user_id,
            result="SUCCESS",
            details=f"User account '{username}' was created."
        )

        db.session.commit()

        return user

    except Exception:
        db.session.rollback()
        raise

def disable_user(target_user_id, admin_user_id):
    """Disable an application account without deleting its history."""

    try:
        admin = require_admin(admin_user_id)

        target_user = User.query.filter_by(
            user_id=target_user_id
        ).first()

        if target_user is None:
            raise ValueError("User not found.")

        if not target_user.is_active:
            raise ValueError("User is already disabled.")

        # Prevent an Administrator from disabling their own active account.
        if target_user.user_id == admin.user_id:
            raise ValueError(
                "Administrators cannot disable their own account."
            )

        target_user.is_active = False

        write_audit_log(
            user_id=admin.user_id,
            action="USER_DISABLED",
            target_type="User",
            target_id=target_user.user_id,
            result="SUCCESS",
            details=f"User account '{target_user.username}' was disabled."
        )

        db.session.commit()

        return target_user

    except Exception:
        db.session.rollback()
        raise

def change_user_role(target_user_id, new_role_name, admin_user_id):
    """Assign a valid role to an existing user."""

    try:
        admin = require_admin(admin_user_id)

        target_user = User.query.filter_by(
            user_id=target_user_id
        ).first()

        if target_user is None:
            raise ValueError("User not found.")

        new_role = Role.query.filter_by(
            name=new_role_name,
            is_active=True
        ).first()

        if new_role is None:
            raise ValueError("Invalid or inactive role.")

        old_role = target_user.role.name

        target_user.role_id = new_role.role_id

        write_audit_log(
            user_id=admin.user_id,
            action="ROLE_CHANGED",
            target_type="User",
            target_id=target_user.user_id,
            result="SUCCESS",
            details=(
                f"User '{target_user.username}' changed "
                f"from {old_role} to {new_role.name}."
            )
        )

        db.session.commit()

        return target_user

    except Exception:
        db.session.rollback()
        raise

def create_room(name, admin_user_id, description=None, capacity=None):
    """Create a new gallery room."""

    try:
        admin = require_admin(admin_user_id)

        if Room.query.filter_by(name=name).first():
            raise ValueError("Room name already exists.")

        if capacity is not None and capacity < 1:
            raise ValueError("Room capacity must be greater than zero.")

        room = Room(
            name=name,
            description=description,
            capacity=capacity
        )

        db.session.add(room)
        db.session.flush()

        write_audit_log(
            user_id=admin.user_id,
            action="ROOM_CREATED",
            target_type="Room",
            target_id=room.room_id,
            result="SUCCESS",
            details=f"Gallery room '{room.name}' was created."
        )

        db.session.commit()

        return room

    except Exception:
        db.session.rollback()
        raise

def create_person(name, identifier, admin_user_id):
    """Create a tracked person record."""

    try:
        admin = require_admin(admin_user_id)

        if Person.query.filter_by(identifier=identifier).first():
            raise ValueError("Person identifier already exists.")

        person = Person(
            name=name,
            identifier=identifier
        )

        db.session.add(person)
        db.session.flush()

        write_audit_log(
            user_id=admin.user_id,
            action="PERSON_CREATED",
            target_type="Person",
            target_id=person.person_id,
            result="SUCCESS",
            details=f"Tracked person '{person.name}' was created."
        )

        db.session.commit()

        return person

    except Exception:
        db.session.rollback()
        raise
