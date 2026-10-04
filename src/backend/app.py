from flask import Flask
from database import db
from models import Role, User, Person, Room, GalleryEvent, AuditLog
from services import (
    record_gallery_entry,
    record_gallery_exit,
    record_room_entry,
    record_room_exit
)

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///gallery.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

# Initialization
with app.app_context():
    db.create_all()

    if Role.query.count() == 0:
        guest = Role(
            name="Guest",
            description="Standard authenticated user"
        )

        employee = Role(
            name="Employee",
            description="Gallery staff member"
        )

        administrator = Role(
            name="Administrator",
            description="Privileged application administrator"
        )

        db.session.add_all([
            guest,
            employee,
            administrator
        ])

        db.session.commit()

    # Create one administrator account for testing.
    if User.query.count() == 0:
        admin_role = Role.query.filter_by(
            name="Administrator"
        ).first()

        admin_user = User(
            username="admin",
            role_id=admin_role.role_id,
            full_name="Test Administrator",
            email="admin@example.com"
        )

    # Store only the hashed form of the test password.
        admin_user.set_password("Admin123!")

        db.session.add(admin_user)
        db.session.commit()

    # Seed one tracked person for database testing.
    if Person.query.count() == 0:
        person = Person(
            name="Alice Johnson",
            identifier="GUEST-001"
        )   

        db.session.add(person)
        db.session.commit()


    # Seed one gallery room for database testing.
    if Room.query.count() == 0:
        room = Room(
            name="Modern Art",
            description="Modern and contemporary art gallery",
            capacity=50
        )

        db.session.add(room)
        db.session.commit()

    # Seed one gallery entry event for testing.
    #if GalleryEvent.query.count() == 0:
     #   person = Person.query.filter_by(
      #      identifier="GUEST-001"
       # ).first()
#
 #       admin_user = User.query.filter_by(
  #          username="admin"
   #     ).first()
#
 #       event = GalleryEvent(
  #          person_id=person.person_id,
   #         room_id=None,
    #        user_id=admin_user.user_id,
     #       event_type="GALLERY_ENTER"
      #  )
#
 #       # Only store recognized gallery event types.
  #      if event.is_valid_event_type():
   #         db.session.add(event)
    #        db.session.commit()

    # Seed one audit record for testing.
#    if AuditLog.query.count() == 0:
 #       admin_user = User.query.filter_by(
  #          username="admin"
   #     ).first()

    #    audit = AuditLog(
     #       user_id=admin_user.user_id,
      #      action="GALLERY_ENTRY_RECORDED",
       #     target_type="GalleryEvent",
        #    target_id=1,
         #   result="SUCCESS",
          #  details="Initial test gallery entry recorded."
        #)

        #db.session.add(audit)
        #db.session.commit()


@app.route("/")
def home():
    person = Person.query.filter_by(
        identifier="GUEST-001"
    ).first()

    admin = User.query.filter_by(
        username="admin"
    ).first()

    try:
        # First entry should succeed.
        record_gallery_entry(
            person.person_id,
            admin.user_id
        )

        # Second entry should fail because the person is already inside.
        record_gallery_entry(
            person.person_id,
            admin.user_id
        )

        return "TEST FAILED: Duplicate gallery entry was allowed."

    except ValueError as error:
        return f"TEST PASSED: {error}"

    except PermissionError as error:
        return f"TEST FAILED: Unexpected permission error: {error}"

if __name__ == "__main__":
    app.run(debug=True)