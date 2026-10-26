# BIBIFI-Group-6
# Secure Gallery Access Tracker

## Project Overview

The Secure Gallery Access Tracker is a Flask-based web application for tracking guests and employees entering and leaving an art gallery and its individual rooms.

## Team Members

- Matthew Wear
- Brandon Renner

## Technology Stack

- Python
- Flask
- HTML/CSS
- Jinja
- SQLAlchemy
- SQLite

## User Roles

- Guest/User
- Employee
- Administrator

## Core Functionality

- User authentication
- Gallery entry/exit tracking
- Room entry/exit tracking
- Current occupancy
- Historical event searches
- Administrative functions
- Audit logging

## Development Setup

Create a virtual environment:

```powershell
py -m venv .venv
```

Install the project dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the Flask application:

```powershell
.\.venv\Scripts\python.exe src/backend/app.py
```

The application will be available at:

`http://127.0.0.1:5000`

## Database

The application uses SQLite with Flask-SQLAlchemy for persistent storage.

### Database Files

- `src/backend/database.py` - Shared SQLAlchemy database instance.
- `src/backend/models.py` - Defines database models and relationships.
- `src/backend/services.py` - Implements gallery movement business logic and database transactions.
- `database/schema.sql` - SQL schema for recreating the database manually.
- `database/seed.sql` - Initial non-sensitive seed data.
- `instance/gallery.db` - Local development database. This file is not committed to Git.

### Database Models

The database contains the following primary entities:

- `Role` - Guest, Employee, and Administrator roles.
- `User` - Authenticated application accounts.
- `Person` - Guests or employees whose gallery location is tracked.
- `Room` - Gallery rooms.
- `GalleryEvent` - Gallery and room entry/exit events.
- `AuditLog` - Security-relevant and administrative activity.

### Gallery Event Types

The application supports four gallery event types:

- `GALLERY_ENTER`
- `GALLERY_EXIT`
- `ROOM_ENTER`
- `ROOM_EXIT`

Database and service-layer validation restrict events to these values.

### Business Logic

The database service layer prevents invalid gallery states, including:

- Duplicate gallery entry.
- Gallery exit while already outside.
- Room entry while outside the gallery.
- Occupying multiple rooms simultaneously.
- Leaving a room the person does not currently occupy.
- Guests recording Employee-only gallery events.

Valid movement events and their audit records are committed together using database transactions.

### Database Testing

Database tests use temporary in-memory SQLite databases and do not modify the development database.

Run all tests from the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Current database test coverage includes:

- Business-logic validation
- Role-based event authorization
- Valid gallery movement sequences
- Event ordering
- Audit-log generation
- Database `CHECK` constraints
- Schema creation
- Seed-data creation and duplicate protection

The current database test suite contains **26 passing tests**.