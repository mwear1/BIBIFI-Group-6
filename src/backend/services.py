from datetime import datetime, time, timedelta

from database import db
from models import Role, User, UserSession, Person, Room, GalleryEvent, AuditLog


def _acquire_person_movement_write_lock(person_id):
    """Acquire SQLite's writer lock before reading movement state."""
    db.session.query(Person).filter_by(person_id=person_id).update(
        {Person.person_id: Person.person_id},
        synchronize_session=False,
    )


def _acquire_room_capacity_write_lock(room_id):
    """Acquire SQLite's writer lock before checking or changing capacity."""
    db.session.query(Room).filter_by(room_id=room_id).update(
        {Room.room_id: Room.room_id},
        synchronize_session=False,
    )

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
        _acquire_person_movement_write_lock(person_id)
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
        _acquire_person_movement_write_lock(person_id)
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
        _acquire_person_movement_write_lock(person_id)
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

        # A configured capacity is a hard limit. The movement write lock above
        # serializes this occupancy check with concurrent room-entry requests.
        if (
            room.capacity is not None
            and len(get_room_occupancy(room.room_id)) >= room.capacity
        ):
            raise ValueError("Room is at capacity.")

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
        _acquire_person_movement_write_lock(person_id)
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
    limit=100,
    page=1,
    date_from=None,
    date_to=None,
):
    """Return one bounded page of optionally date-filtered gallery events."""
    query = GalleryEvent.query
    if person_id is not None:
        query = query.filter(GalleryEvent.person_id == person_id)
    if room_id is not None:
        query = query.filter(GalleryEvent.room_id == room_id)
    if event_type is not None:
        if event_type not in {"GALLERY_ENTER", "GALLERY_EXIT", "ROOM_ENTER", "ROOM_EXIT"}:
            raise ValueError("Invalid event type.")
        query = query.filter(GalleryEvent.event_type == event_type)
    if type(limit) is not int or limit < 1 or limit > 500:
        raise ValueError("Limit must be between 1 and 500.")
    if type(page) is not int or page < 1 or page > 10000:
        raise ValueError("Page must be between 1 and 10000.")
    if (date_from is None) != (date_to is None):
        raise ValueError("date_from and date_to must be provided together.")
    if date_from is not None:
        try:
            first_day = datetime.strptime(date_from, "%Y-%m-%d").date()
            last_day = datetime.strptime(date_to, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            raise ValueError("Dates must use YYYY-MM-DD format.")
        if last_day < first_day:
            raise ValueError("date_to must not be earlier than date_from.")
        if (last_day - first_day).days > 365:
            raise ValueError("Date range cannot exceed 366 days.")
        query = query.filter(
            GalleryEvent.timestamp >= datetime.combine(first_day, time.min),
            GalleryEvent.timestamp < datetime.combine(last_day + timedelta(days=1), time.min),
        )
    return (
        query.order_by(GalleryEvent.event_id.desc())
        .limit(limit)
        .offset((page - 1) * limit)
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

        UserSession.query.filter_by(
            user_id=target_user.user_id,
            revoked_at=None
        ).update(
            {UserSession.revoked_at: db.func.now()},
            synchronize_session=False
        )

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

        # Prevent removal of the final active Administrator account.
        if (
            target_user.is_active
            and target_user.role.name == "Administrator"
            and new_role.name != "Administrator"
        ):
            active_admin_count = (
                User.query
                .join(Role)
                .filter(
                    User.is_active.is_(True),
                    Role.is_active.is_(True),
                    Role.name == "Administrator"
                )
                .count()
            )

            if active_admin_count <= 1:
                raise ValueError(
                    "The last active Administrator cannot be demoted."
                )

        old_role = target_user.role.name
        target_user.role_id = new_role.role_id

        UserSession.query.filter_by(
            user_id=target_user.user_id,
            revoked_at=None
        ).update(
            {UserSession.revoked_at: db.func.now()},
            synchronize_session=False
        )

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


def update_user(target_user_id, admin_user_id, **changes):
    """Update allowlisted account fields and revoke sessions on password change."""
    try:
        admin = require_admin(admin_user_id)
        target = db.session.get(User, target_user_id)
        if target is None:
            raise ValueError("User not found.")
        allowed = {"username", "full_name", "email", "password"}
        if not changes or set(changes) - allowed:
            raise ValueError("Provide valid account fields to update.")
        if "username" in changes:
            username = changes["username"]
            if not isinstance(username, str) or not username.strip() or len(username) > 80:
                raise ValueError("username must contain 1 to 80 characters.")
            username = username.strip()
            duplicate = User.query.filter(
                User.username == username, User.user_id != target_user_id
            ).first()
            if duplicate:
                raise ValueError("Username already exists.")
            target.username = username
        if "full_name" in changes:
            value = changes["full_name"]
            if value is not None and (not isinstance(value, str) or len(value) > 100):
                raise ValueError("full_name must be at most 100 characters.")
            target.full_name = value
        if "email" in changes:
            value = changes["email"] or None
            if value is not None and (not isinstance(value, str) or len(value) > 120):
                raise ValueError("email must be at most 120 characters.")
            duplicate = User.query.filter(
                User.email == value, User.user_id != target_user_id
            ).first() if value else None
            if duplicate:
                raise ValueError("Email already exists.")
            target.email = value
        password_changed = "password" in changes
        if password_changed:
            password = changes["password"]
            if not isinstance(password, str) or not 12 <= len(password) <= 1024:
                raise ValueError("password must contain 12 to 1024 characters.")
            target.set_password(password)
            UserSession.query.filter_by(
                user_id=target.user_id, revoked_at=None
            ).update(
                {UserSession.revoked_at: db.func.now()},
                synchronize_session=False,
            )
        write_audit_log(
            user_id=admin.user_id,
            action="USER_UPDATED",
            target_type="User",
            target_id=target.user_id,
            result="SUCCESS",
            details="Updated account fields: " + ", ".join(sorted(changes)),
        )
        db.session.commit()
        return target
    except Exception:
        db.session.rollback()
        raise


def set_user_active(target_user_id, active, admin_user_id):
    """Enable or disable an account while preserving its history."""
    try:
        admin = require_admin(admin_user_id)
        target = db.session.get(User, target_user_id)
        if target is None:
            raise ValueError("User not found.")
        if type(active) is not bool:
            raise ValueError("active must be a boolean.")
        if target.is_active == active:
            raise ValueError("Account already has the requested status.")
        if not active and target.user_id == admin.user_id:
            raise ValueError("Administrators cannot disable their own account.")
        target.is_active = active
        if not active:
            UserSession.query.filter_by(
                user_id=target.user_id, revoked_at=None
            ).update(
                {UserSession.revoked_at: db.func.now()},
                synchronize_session=False,
            )
        write_audit_log(
            user_id=admin.user_id,
            action="USER_ENABLED" if active else "USER_DISABLED",
            target_type="User",
            target_id=target.user_id,
            result="SUCCESS",
            details=f"User account '{target.username}' was {'enabled' if active else 'disabled'}.",
        )
        db.session.commit()
        return target
    except Exception:
        db.session.rollback()
        raise


def update_room(target_room_id, admin_user_id, **changes):
    """Update an allowlisted room profile without deleting its history."""
    try:
        admin = require_admin(admin_user_id)
        _acquire_room_capacity_write_lock(target_room_id)
        room = db.session.get(Room, target_room_id)
        if room is None:
            raise ValueError("Room not found.")
        allowed = {"name", "description", "capacity"}
        if not changes or set(changes) - allowed:
            raise ValueError("Provide valid room fields to update.")
        if "name" in changes:
            value = changes["name"]
            if not isinstance(value, str) or not value.strip() or len(value) > 100:
                raise ValueError("name must contain 1 to 100 characters.")
            value = value.strip()
            duplicate = Room.query.filter(
                Room.name == value, Room.room_id != room.room_id
            ).first()
            if duplicate:
                raise ValueError("Room name already exists.")
            room.name = value
        if "description" in changes:
            value = changes["description"]
            if value is not None and (not isinstance(value, str) or len(value) > 255):
                raise ValueError("description must be at most 255 characters.")
            room.description = value
        if "capacity" in changes:
            value = changes["capacity"]
            if value is not None and (type(value) is not int or value < 1):
                raise ValueError("capacity must be a positive integer or null.")
            if value is not None and room.is_active:
                occupancy = len(get_room_occupancy(room.room_id))
                if value < occupancy:
                    raise ValueError(
                        "Capacity cannot be lower than current room occupancy."
                    )
            room.capacity = value
        write_audit_log(
            user_id=admin.user_id, action="ROOM_UPDATED", target_type="Room",
            target_id=room.room_id, result="SUCCESS",
            details="Updated room fields: " + ", ".join(sorted(changes)),
        )
        db.session.commit()
        return room
    except Exception:
        db.session.rollback()
        raise


def set_room_active(target_room_id, active, admin_user_id):
    """Enable or disable a room, retaining all associated event history."""
    try:
        admin = require_admin(admin_user_id)
        room = db.session.get(Room, target_room_id)
        if room is None:
            raise ValueError("Room not found.")
        if type(active) is not bool:
            raise ValueError("active must be a boolean.")
        if room.is_active == active:
            raise ValueError("Room already has the requested status.")
        if not active:
            occupants = []
            for person in Person.query.filter_by(is_active=True).all():
                current = get_current_room(person.person_id)
                if current is not None and current.room_id == room.room_id:
                    occupants.append(person)
            if occupants:
                raise ValueError("A room cannot be disabled while people are inside.")
        room.is_active = active
        write_audit_log(
            user_id=admin.user_id,
            action="ROOM_ENABLED" if active else "ROOM_DISABLED",
            target_type="Room", target_id=room.room_id, result="SUCCESS",
            details=f"Room '{room.name}' was {'enabled' if active else 'disabled'}.",
        )
        db.session.commit()
        return room
    except Exception:
        db.session.rollback()
        raise


def update_person(target_person_id, admin_user_id, **changes):
    """Update a tracked person's identifying information."""
    try:
        admin = require_admin(admin_user_id)
        person = db.session.get(Person, target_person_id)
        if person is None:
            raise ValueError("Person not found.")
        allowed = {"name", "identifier"}
        if not changes or set(changes) - allowed:
            raise ValueError("Provide valid person fields to update.")
        if "name" in changes:
            value = changes["name"]
            if not isinstance(value, str) or not value.strip() or len(value) > 100:
                raise ValueError("name must contain 1 to 100 characters.")
            person.name = value.strip()
        if "identifier" in changes:
            value = changes["identifier"]
            if not isinstance(value, str) or not value.strip() or len(value) > 100:
                raise ValueError("identifier must contain 1 to 100 characters.")
            value = value.strip()
            duplicate = Person.query.filter(
                Person.identifier == value, Person.person_id != person.person_id
            ).first()
            if duplicate:
                raise ValueError("Person identifier already exists.")
            person.identifier = value
        write_audit_log(
            user_id=admin.user_id, action="PERSON_UPDATED",
            target_type="Person", target_id=person.person_id,
            result="SUCCESS",
            details="Updated tracked-person fields: " + ", ".join(sorted(changes)),
        )
        db.session.commit()
        return person
    except Exception:
        db.session.rollback()
        raise


def set_person_active(target_person_id, active, admin_user_id):
    """Enable or disable a tracked person without invalidating occupancy state."""
    try:
        admin = require_admin(admin_user_id)
        person = db.session.get(Person, target_person_id)
        if person is None:
            raise ValueError("Person not found.")
        if type(active) is not bool:
            raise ValueError("active must be a boolean.")
        if person.is_active == active:
            raise ValueError("Person already has the requested status.")
        if not active and (
            is_inside_gallery(person.person_id)
            or get_current_room(person.person_id) is not None
        ):
            raise ValueError("A person must exit the gallery before being disabled.")
        person.is_active = active
        write_audit_log(
            user_id=admin.user_id,
            action="PERSON_ENABLED" if active else "PERSON_DISABLED",
            target_type="Person", target_id=person.person_id,
            result="SUCCESS",
            details=f"Tracked person '{person.name}' was {'enabled' if active else 'disabled'}.",
        )
        db.session.commit()
        return person
    except Exception:
        db.session.rollback()
        raise
