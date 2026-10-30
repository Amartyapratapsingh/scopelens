-- SYNTHETIC FIXTURE FILE — not real data.
-- Exists only so the `labs-bad` fixture serves a sensitive-looking backup path.
CREATE TABLE fixture_users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);
INSERT INTO fixture_users (id, email) VALUES (1, 'fixture.user@example.invalid');
