from flask import Flask

from database import db

# Import models so SQLAlchemy knows which tables to create.
from models import Role, User, Person, Room, GalleryEvent, AuditLog


app = Flask(__name__)

# Configure the local SQLite database.
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///gallery.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Attach SQLAlchemy to the Flask application.
db.init_app(app)


with app.app_context():
    # Create any database tables that do not already exist.
    db.create_all()


@app.route("/")
def home():
    return "Secure Gallery Access Tracker"


if __name__ == "__main__":
    app.run(debug=True)