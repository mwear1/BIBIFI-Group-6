from database import db
from sqlalchemy import event as sqlalchemy_event
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

class UserSession(db.Model):
    """Server-side login session that can be revoked on logout."""

    __tablename__ = "user_sessions"

    session_id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False,
        index=True,
    )
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
    )
    expires_at = db.Column(db.DateTime, nullable=False)
    last_seen_at = db.Column(db.DateTime)
    revoked_at = db.Column(db.DateTime)

    user = db.relationship("User", backref="sessions")

    def __repr__(self):
        return f"<UserSession {self.session_id}>"

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
    __tablename__ = "gallery_events"

    # Restrict events to the four supported movement types.
    __table_args__ = (
        db.CheckConstraint(
            "event_type IN "
            "('GALLERY_ENTER', 'GALLERY_EXIT', 'ROOM_ENTER', 'ROOM_EXIT')",
            name="ck_gallery_events_event_type"
        ),
    )

    event_id = db.Column(db.Integer, primary_key=True)

    # Person whose movement is being recorded.
    person_id = db.Column(
        db.Integer,
        db.ForeignKey("persons.person_id"),
        nullable=False
    )

    # Room is only required for room-specific events.
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

    event_type = db.Column(db.String(30), nullable=False)

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now()
    )

    person = db.relationship("Person", backref="gallery_events")
    room = db.relationship("Room", backref="gallery_events")
    user = db.relationship("User", backref="recorded_events")

    def is_valid_event_type(self):
        return self.event_type in VALID_EVENT_TYPES

    def __repr__(self):
        return f"<GalleryEvent {self.event_type}>"

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    # Audit results must have a known status.
    __table_args__ = (
        db.CheckConstraint(
            "result IN ('SUCCESS', 'FAILURE')",
            name="ck_audit_logs_result"
        ),
    )

    audit_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=True
    )

    action = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50))
    target_id = db.Column(db.Integer)
    result = db.Column(db.String(20), nullable=False)
    details = db.Column(db.Text)

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now()
    )

    user = db.relationship("User", backref="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action}>"

class LoginThrottle(db.Model):
    """Persistent per-client login failure window; stores no raw IP address."""

    __tablename__ = "login_throttles"

    ip_hash = db.Column(db.String(64), primary_key=True)
    window_started_at = db.Column(db.DateTime, nullable=False)
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    blocked_until = db.Column(db.DateTime)

    __table_args__ = (
        db.CheckConstraint(
            "failure_count >= 0",
            name="ck_login_throttles_failure_count",
        ),
    )

    def __repr__(self):
        return f"<LoginThrottle {self.ip_hash[:8]}>"


@sqlalchemy_event.listens_for(AuditLog, "before_update")
@sqlalchemy_event.listens_for(AuditLog, "before_delete")
def _reject_audit_log_mutation(mapper, connection, target):
    """Keep application-level audit records append-only."""
    raise ValueError("Audit log records cannot be changed or deleted.")


def install_audit_log_triggers(connection):
    """Reject SQLite bulk and direct SQL changes to audit rows."""
    if connection.dialect.name != "sqlite":
        return
    connection.exec_driver_sql("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_update
        BEFORE UPDATE ON audit_logs
        BEGIN SELECT RAISE(ABORT, 'audit logs are append-only'); END
    """)
    connection.exec_driver_sql("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_delete
        BEFORE DELETE ON audit_logs
        BEGIN SELECT RAISE(ABORT, 'audit logs are append-only'); END
    """)


@sqlalchemy_event.listens_for(AuditLog.__table__, "after_create")
def _install_audit_log_triggers_after_create(target, connection, **kwargs):
    install_audit_log_triggers(connection)
