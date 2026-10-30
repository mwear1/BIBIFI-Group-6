"""Shared test configuration."""

import os


# The Flask application creates its tables during import. Point it at an
# in-memory database before API tests import it so tests never touch gallery.db.
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
