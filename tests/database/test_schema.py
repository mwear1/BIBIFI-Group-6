import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"
SEED_PATH = PROJECT_ROOT / "database" / "seed.sql"


def create_test_database():
    """Build a temporary SQLite database from the SQL files."""

    connection = sqlite3.connect(":memory:")

    # SQLite requires foreign-key enforcement to be enabled per connection.
    connection.execute("PRAGMA foreign_keys = ON;")

    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    seed = SEED_PATH.read_text(encoding="utf-8")

    connection.executescript(schema)
    connection.executescript(seed)

    return connection

def test_schema_creates_required_tables():
    """schema.sql should create every required database table."""

    connection = create_test_database()

    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table';
        """
    ).fetchall()

    table_names = {row[0] for row in rows}

    expected_tables = {
        "roles",
        "users",
        "login_throttles",
        "persons",
        "rooms",
        "gallery_events",
        "audit_logs"
    }

    assert expected_tables.issubset(table_names)

    connection.close()

def test_seed_creates_required_roles():
    """seed.sql should create the three required application roles."""

    connection = create_test_database()

    rows = connection.execute(
        """
        SELECT name
        FROM roles
        ORDER BY role_id;
        """
    ).fetchall()

    roles = [row[0] for row in rows]

    assert roles == [
        "Guest",
        "Employee",
        "Administrator"
    ]

    connection.close()

def test_seed_can_run_twice_without_duplicates():
    """Seed data should be safe to apply more than once."""

    connection = create_test_database()

    seed = SEED_PATH.read_text(encoding="utf-8")
    connection.executescript(seed)

    role_count = connection.execute(
        "SELECT COUNT(*) FROM roles;"
    ).fetchone()[0]

    assert role_count == 3

    connection.close()