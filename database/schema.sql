-- Enable foreign-key enforcement in SQLite.
PRAGMA foreign_keys = ON;


-- Defines application roles such as Guest, Employee, and Administrator.
CREATE TABLE IF NOT EXISTS roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT 1
);


-- Stores authenticated application users.
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) NOT NULL UNIQUE,

    -- Only password hashes are stored; plaintext passwords are never stored.
    password_hash VARCHAR(255) NOT NULL,

    role_id INTEGER NOT NULL,
    full_name VARCHAR(100),
    email VARCHAR(120) UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (role_id)
        REFERENCES roles(role_id)
);


-- Stores people whose physical location is tracked in the gallery.
CREATE TABLE IF NOT EXISTS persons (
    person_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    identifier VARCHAR(100) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT 1
);


-- Stores gallery rooms.
CREATE TABLE IF NOT EXISTS rooms (
    room_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    capacity INTEGER,
    is_active BOOLEAN NOT NULL DEFAULT 1
);


-- Stores gallery and room movement events.
CREATE TABLE IF NOT EXISTS gallery_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,

    person_id INTEGER NOT NULL,
    room_id INTEGER,
    user_id INTEGER NOT NULL,

    event_type VARCHAR(30) NOT NULL
    CHECK (
        event_type IN (
            'GALLERY_ENTER',
            'GALLERY_EXIT',
            'ROOM_ENTER',
            'ROOM_EXIT'
        )
    ),
    
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (person_id)
        REFERENCES persons(person_id),

    FOREIGN KEY (room_id)
        REFERENCES rooms(room_id),

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
);


-- Stores security-relevant and administrative activity.
CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id INTEGER,
    result VARCHAR(20) NOT NULL
        CHECK (result IN ('SUCCESS', 'FAILURE')),
    details TEXT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
);