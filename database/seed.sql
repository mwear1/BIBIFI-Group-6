-- Required application roles.
INSERT OR IGNORE INTO roles (name, description)
VALUES
    ('Guest', 'Standard authenticated user'),
    ('Employee', 'Gallery staff member'),
    ('Administrator', 'Privileged application administrator');


-- Initial gallery rooms.
INSERT OR IGNORE INTO rooms (name, description, capacity)
VALUES
    (
        'Modern Art',
        'Modern and contemporary art gallery',
        50
    ),
    (
        'Photography',
        'Photography gallery',
        40
    ),
    (
        'Sculpture Gallery',
        'Gallery containing sculptures and three-dimensional artwork',
        35
    );