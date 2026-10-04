from database import db
from werkzeug.security import generate_password_hash, check_password_hash


class Role(db.Model):
    __tablename__ = "roles"

    role_id = db.Column(db.Integer, primary_key=True)

    # Role names must be unique so permissions map consistently.
    name = db.Column(db.String(50), unique=True, nullable=False)

    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)

    # Usernames are unique identifiers for authentication.
    username = db.Column(db.String(80), unique=True, nullable=False)

    # Only a password hash is stored, never the plaintext password.
    password_hash = db.Column(db.String(255), nullable=False)

    # Each user must reference a valid role.
    role_id = db.Column(
        db.Integer,
        db.ForeignKey("roles.role_id"),
        nullable=False
    )

    full_name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Automatically records when the account was created.
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now()
    )

    # Allows access to the related Role object through user.role.
    role = db.relationship(
        "Role",
        backref="users"
    )

    # Hash the password before storing it in the database.
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Compare a supplied password against the stored hash.
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class Person(db.Model):
    __tablename__ = "persons"

    person_id = db.Column(db.Integer, primary_key=True)

    # Name of the guest or employee being tracked.
    name = db.Column(db.String(100), nullable=False)

    # Unique identifier used to distinguish tracked persons.
    identifier = db.Column(db.String(100), unique=True, nullable=False)

    # Allows records to be disabled without deleting history.
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f"<Person {self.name}>"

class Room(db.Model):
    __tablename__ = "rooms"

    room_id = db.Column(db.Integer, primary_key=True)

    # Room names must be unique within the gallery.
    name = db.Column(db.String(100), unique=True, nullable=False)

    description = db.Column(db.String(255))

    # Optional occupancy limit for the room.
    capacity = db.Column(db.Integer)

    is_active = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f"<Room {self.name}>"

VALID_EVENT_TYPES = {
    "GALLERY_ENTER",
    "GALLERY_EXIT",
    "ROOM_ENTER",
    "ROOM_EXIT"
}

class GalleryEvent(db.Model):
    # Validate event types before storing them.
    def is_valid_event_type(self):
        return self.event_type in VALID_EVENT_TYPES
    
    __tablename__ = "gallery_events"

    event_id = db.Column(db.Integer, primary_key=True)

    # Person whose movement is being recorded.
    person_id = db.Column(
        db.Integer,
        db.ForeignKey("persons.person_id"),
        nullable=False
    )

    # Room is only needed for room entry/exit events.
    room_id = db.Column(
        db.Integer,
        db.ForeignKey("rooms.room_id"),
        nullable=True
    )

    # User who recorded the event.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    # Expected values:
    # GALLERY_ENTER, GALLERY_EXIT, ROOM_ENTER, ROOM_EXIT
    event_type = db.Column(db.String(30), nullable=False)

    # Automatically record when the event was created.
    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now()
    )

    # Relationships make related objects easier to access.
    person = db.relationship("Person", backref="gallery_events")
    room = db.relationship("Room", backref="gallery_events")
    user = db.relationship("User", backref="recorded_events")

    def __repr__(self):
        return f"<GalleryEvent {self.event_type}>"

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    audit_id = db.Column(db.Integer, primary_key=True)

    # User responsible for the action, when known.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=True
    )

    # Short description of the action performed.
    action = db.Column(db.String(100), nullable=False)

    # Type of object affected, such as User, Room, or GalleryEvent.
    target_type = db.Column(db.String(50))

    # ID of the affected object when applicable.
    target_id = db.Column(db.Integer)

    # Result of the action, such as SUCCESS or FAILURE.
    result = db.Column(db.String(20), nullable=False)

    # Additional non-sensitive details about the event.
    details = db.Column(db.Text)

    # Automatically records when the audit event occurred.
    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now()
    )

    # Allows access to the related User object through audit.user.
    user = db.relationship("User", backref="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action}>"