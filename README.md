# BIBIFI Group 6 - Secure Gallery Access Tracker

## Project Overview

The Secure Gallery Access Tracker is a Flask-based application for recording and monitoring guests' and employees' movement through an art gallery. Employees and Administrators can record gallery and room entry or exit, view occupancy, and search event history. Administrators can also manage accounts, roles, rooms, tracked persons, and audit information.

The application provides a browser dashboard for gallery staff and administrators alongside its JSON API. Guests can sign in and view their account; movement and occupancy information is restricted to staff.

## Team Members

- Matthew Wear
- Brandon Renner

## Technology Stack

- Python
- Flask
- Flask-SQLAlchemy
- SQLAlchemy
- SQLite
- Werkzeug password hashing

## Roles

- **Guest** - Can log in and view their own account information.
- **Employee** - Can record gallery events and view occupancy, person locations, and event history.
- **Administrator** - Has Employee permissions and can manage user accounts, roles, rooms, tracked persons, and audit information.

Authorization is enforced on the server for each protected endpoint. Hiding an action in a future user interface will not replace these checks.

## Development Setup

Create and activate a virtual environment, then install the dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Set a persistent Flask signing key before starting the application. Generate a random key with:

```powershell
$env:FLASK_SECRET_KEY = py -c "import secrets; print(secrets.token_urlsafe(48))"
```

Keep the key private and out of source control. In development, the app creates an ephemeral key if `FLASK_SECRET_KEY` is unset; sessions will stop working when the app restarts. In production, the app requires `FLASK_SECRET_KEY`.

For HTTPS deployments, set:

```powershell
$env:APP_ENV = "production"
$env:FLASK_COOKIE_SECURE = "1"
```

The cookie is HttpOnly and SameSite=Lax. `DATABASE_URL` can be set to override the default SQLite database location.

Run the application from the project root with Flask's module loader:

```powershell
.\.venv\Scripts\python.exe -m flask --app src/backend/app.py run --host 127.0.0.1 --port 5000
```

Use this command for normal development. It loads the same app module and default SQLite database (`src/backend/instance/gallery.db`) used by Flask CLI commands such as `create-admin`. Do not start the app with `python src/backend/app.py`, which selects a different default instance folder.

The browser interface opens at the application root. Sign in with an account created by an Administrator. The dashboard shows current gallery occupancy, room counts, and recent movement; the Events page records movement and filters history; the Administration page manages accounts, tracked people, rooms, and audit activity.

The local development server is available at:

`http://127.0.0.1:5000`

## Initial Administrator

On a fresh database, create the first Administrator with the interactive Flask command. The password prompt does not display the password:

```powershell
.\.venv\Scripts\python.exe -m flask --app src/backend/app.py create-admin
```

The application creates the database tables and built-in Guest, Employee, and Administrator roles on startup. Administrators can create additional accounts through the API.

## Database

The application uses SQLite with Flask-SQLAlchemy.

Important database files:

- `src/backend/database.py` - Shared SQLAlchemy database instance.
- `src/backend/models.py` - Defines the database models and relationships.
- `src/backend/services.py` - Implements gallery movement and administrative business logic.
- `database/schema.sql` - SQL schema for manual database setup.
- `database/seed.sql` - Initial roles and room data for manual seeding.
- `src/backend/instance/gallery.db` - Default local development database; ignored by Git.

### Models

- `Role` - Guest, Employee, and Administrator roles.
- `User` - Application accounts and password hashes.
- `UserSession` - Hashed, expiring, revocable login sessions.
- `LoginThrottle` - Per-client login failure windows keyed by an HMAC of the client address.
- `Person` - A tracked guest or employee; does not need an application account.
- `Room` - A gallery room.
- `GalleryEvent` - Gallery or room entry and exit history.
- `AuditLog` - Security-relevant and administrative activity.

### Gallery Event Types

- `GALLERY_ENTER`
- `GALLERY_EXIT`
- `ROOM_ENTER`
- `ROOM_EXIT`

The database and service layer restrict events to these types and validate movement state before recording an event.

## Authentication and Sessions

Login uses a username and password. Passwords are hashed using Werkzeug and are never returned by the API.

After successful login, Flask sets a signed, HttpOnly session cookie. The database stores only a hash of the random session token. Sessions have a 30-minute absolute lifetime and a 15-minute idle timeout, refreshed after successful authenticated requests. Logout, account disablement, password changes, and role changes revoke the corresponding server-side session records.

The login response also includes a CSRF token. Include it in the `X-CSRF-Token` header on every authenticated `POST`, `PUT`, `PATCH`, or `DELETE` request.

Login attempts are limited to five failed requests from one client address in a 15-minute window. After the fifth failure, that address is blocked from logging in for 15 minutes. The database stores an HMAC digest of the address rather than the raw value; a successful login clears that address's failure counter.

Example login request:

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "employee1",
  "password": "your-password"
}
```

Keep the returned session cookie and CSRF token private. Do not place credentials or tokens in URLs.

## API

The API accepts and returns JSON. Protected endpoints require a valid login session. Unless stated otherwise, state-changing endpoints require the `X-CSRF-Token` header.

| Method | Endpoint                             | Access                  | Purpose                                         |
| ------ | ------------------------------------ | ----------------------- | ----------------------------------------------- |
| `GET`  | `/`                                  | Public                  | Redirect to the browser login or dashboard       |
| `GET`  | `/login`                             | Public                  | Browser sign-in page                             |
| `GET`  | `/dashboard`                         | Authenticated           | Browser occupancy dashboard                      |
| `GET`  | `/events`                            | Employee, Administrator | Browser movement and history                     |
| `GET`  | `/admin`                             | Administrator           | Browser account, room, person, and audit tools   |
| `GET`  | `/healthz`                           | Public                  | Health/status JSON response                      |
| `GET`  | `/api/persons`                       | Employee, Administrator | List active tracked people                       |
| `GET`  | `/api/rooms`                         | Employee, Administrator | List active rooms                                |
| `GET`  | `/api/occupancy/rooms`                | Employee, Administrator | Occupancy summaries for active rooms            |
| `PUT`  | `/api/admin/users/{user_id}`          | Administrator           | Update account username, contact fields, or password |
| `POST` | `/api/auth/login`                    | Public                  | Log in with `username` and `password`           |
| `POST` | `/api/auth/logout`                   | Authenticated           | Revoke the current session                      |
| `GET`  | `/api/auth/me`                       | Authenticated           | View the current user's account                 |
| `GET`  | `/api/occupancy/gallery`             | Employee, Administrator | View current gallery occupants                  |
| `GET`  | `/api/occupancy/rooms/{room_id}`     | Employee, Administrator | View current occupants of a room                |
| `GET`  | `/api/persons/{person_id}/location`  | Employee, Administrator | View a tracked person's current location        |
| `GET`  | `/api/events`                        | Employee, Administrator | Search event history                            |
| `POST` | `/api/events/gallery/entry`          | Employee, Administrator | Record gallery entry; JSON `{ "person_id": 1 }` |
| `POST` | `/api/events/gallery/exit`           | Employee, Administrator | Record gallery exit; JSON `{ "person_id": 1 }`  |
| `POST` | `/api/events/rooms/{room_id}/entry`  | Employee, Administrator | Record room entry; JSON `{ "person_id": 1 }`    |
| `POST` | `/api/events/rooms/{room_id}/exit`   | Employee, Administrator | Record room exit; JSON `{ "person_id": 1 }`     |
| `POST` | `/api/admin/users`                   | Administrator           | Create a user account                           |
| `POST` | `/api/admin/users/{user_id}/disable` | Administrator           | Disable an account and revoke its sessions      |
| `POST` | `/api/admin/users/{user_id}/enable`  | Administrator           | Re-enable a disabled account                    |
| `PUT`  | `/api/admin/users/{user_id}/role`    | Administrator           | Change a user's role and revoke its sessions    |
| `GET`  | `/api/admin/rooms`                   | Administrator           | List all rooms, including disabled rooms        |
| `PUT`  | `/api/admin/rooms/{room_id}`         | Administrator           | Update room name, description, or capacity       |
| `POST` | `/api/admin/rooms/{room_id}/disable` | Administrator           | Disable an unoccupied room                       |
| `POST` | `/api/admin/rooms/{room_id}/enable`  | Administrator           | Re-enable a room                                 |
| `GET`  | `/api/admin/persons`                 | Administrator           | List all tracked persons, including disabled    |
| `PUT`  | `/api/admin/persons/{person_id}`     | Administrator           | Update a tracked person name or identifier       |
| `POST` | `/api/admin/persons/{person_id}/disable` | Administrator        | Disable a person who is outside the gallery     |
| `POST` | `/api/admin/persons/{person_id}/enable` | Administrator         | Re-enable a tracked person                      |
| `GET`  | `/api/admin/audit-logs`              | Administrator           | View recent audit records                       |

The event history endpoint accepts optional person_id, room_id, event_type, date_from, date_to, page, and limit query parameters. Dates use YYYY-MM-DD, must be supplied together, and may span at most 366 days. Pages range from 1 to 10000. The limit must be between 1 and 500; it defaults to 100.

The user creation endpoint accepts `username`, `password`, `role`, and optional `full_name` and `email` fields. Passwords must be 12-1024 characters. Valid roles are `Guest`, `Employee`, and `Administrator`.

The audit log endpoint accepts an optional `limit` query parameter from 1 to 500.

Administrator routes also support editing and enabling/disabling user accounts, rooms, and tracked persons. A room cannot be disabled while occupied, and a tracked person must exit the gallery before being disabled.

### API Error Responses

Errors are returned as JSON for API paths:

```json
{
  "error": "A descriptive error message."
}
```

Authentication failures return a generic username/password error. Login throttling returns HTTP 429 with a `Retry-After` header. Unexpected server errors return a generic response; diagnostic details are written to the server log.

## Security Controls Implemented

- Password hashes instead of plaintext passwords.
- Server-side authentication and role checks.
- Random session tokens with only token hashes stored in the database.
- Absolute and idle session expiration; revocation on logout, account disablement, password change, or role change.
- HttpOnly and SameSite=Lax session cookies; production startup requires a 32-character signing key and Secure cookies.
- Content Security Policy, frame protection, MIME sniffing protection, referrer policy, restricted browser permissions, and production HSTS headers.
- Authenticated API responses are marked Cache-Control: no-store.
- Persistent login throttling: five failures per client address per 15-minute window, with a 15-minute cooldown; only an HMAC of the address is stored.
- Application-level append-only audit records; ORM updates and deletes of existing audit entries are rejected.
- SQLite triggers also reject bulk ORM and direct SQL updates or deletes of audit rows; filesystem permissions must protect the database file.
- Audit records for failed logins, rate-limit activation, expired sessions, CSRF failures, unauthenticated requests, access denials, and rejected requests.
- CSRF-token checks on authenticated state-changing API requests.
- SQLAlchemy ORM queries for database access.
- Server-side input validation and bounded query results.
- Existing service-layer validation for gallery and room movement transitions.
- Successful login/logout, movement, and administrative activity are also audited; logs do not include passwords, session tokens, CSRF tokens, or raw client addresses.
- Generic API responses for unexpected server errors.

## Business Logic

The service layer prevents invalid gallery states, including:

- Duplicate gallery entry.
- Gallery exit while outside.
- Room entry while outside the gallery.
- Occupying multiple rooms simultaneously.
- Leaving a room the person does not currently occupy.
- Leaving the gallery while still inside a room.
- Guests recording Employee-only gallery events.

Successful movement events and their audit records are committed together in a database transaction.
Movement operations acquire the SQLite write lock before checking current state, so concurrent conflicting requests are validated in sequence.

## Tests

The tests use temporary in-memory SQLite databases and do not modify the development database. Run the test suite from the project root with:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Current tests cover:

- Successful login, generic failed-login responses, persistent login throttling, and authentication audit records.
- Authentication requirements and Guest role restrictions.
- CSRF enforcement for state-changing requests.
- Ensuring movement records use the authenticated actor, not a caller-supplied user ID.
- Logout revocation, including rejection of a replayed old cookie.
- Session revocation after account disablement, role changes, expiration, and logout.
- Role-matrix checks, privilege-field allowlisting, SQL-injection payload handling, XSS-safe rendering, security headers, information-disclosure handling, production-cookie configuration, and append-only audit behavior.
- Database schema and seed data, business-logic validation, valid movement sequences, event ordering, audit logging, and database constraints.

## Current Limitations

- Security tests cover representative attack cases; they are not a substitute for the instructor's correctness oracle or a full independent penetration test.
- The login throttle is keyed by `REMOTE_ADDR`; deployments behind a reverse proxy must configure trusted client-address handling before exposing the service.
- Production deployment still requires HTTPS, a protected stable `FLASK_SECRET_KEY`, and a production WSGI server.


