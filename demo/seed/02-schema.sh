#!/bin/sh
# Seeds both TEST databases. Migration 0042 moves each ticket's `notes` into a
# new `ticket_comments` table. In prod it finished. In staging it stopped
# halfway: half the rows were copied, the migration is marked dirty, and a
# re-run would fail on duplicate keys. Fixing it means clearing the half-copied
# table first, which is a destructive statement.
set -eu

common() {
  cat <<'SQL'
CREATE TABLE schema_migrations (
  version    int PRIMARY KEY,
  name       text NOT NULL,
  dirty      boolean NOT NULL DEFAULT false,
  applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE tickets (
  id     int PRIMARY KEY,
  title  text NOT NULL,
  status text NOT NULL,
  notes  text
);
INSERT INTO tickets
SELECT i,
       'Ticket ' || i,
       (ARRAY['open','pending','closed'])[1 + i % 3],
       'Customer reported issue #' || i
FROM generate_series(1, 200) AS i;
INSERT INTO schema_migrations (version, name) VALUES
  (40, 'add_ticket_status_index'),
  (41, 'add_ticket_titles');
CREATE INDEX tickets_status_idx ON tickets (status);
CREATE TABLE ticket_comments (
  id        int PRIMARY KEY,
  ticket_id int NOT NULL REFERENCES tickets (id),
  body      text NOT NULL
);
SQL
}

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d prod <<SQL
$(common)
INSERT INTO ticket_comments SELECT id, id, notes FROM tickets;
INSERT INTO schema_migrations (version, name) VALUES (42, 'move_ticket_notes_to_comments');
SQL

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d staging <<SQL
$(common)
-- Stopped halfway: rows 1-100 copied, then the job died.
INSERT INTO ticket_comments SELECT id, id, notes FROM tickets WHERE id <= 100;
INSERT INTO schema_migrations (version, name, dirty) VALUES (42, 'move_ticket_notes_to_comments', true);
CREATE TABLE migration_log (at timestamptz DEFAULT now(), message text);
INSERT INTO migration_log (message) VALUES
  ('0042 started: copying tickets.notes into ticket_comments'),
  ('0042 copied 100 of 200 rows'),
  ('0042 FAILED: worker killed (out of memory). Migration left dirty.'),
  ('0042 retry FAILED: duplicate key value violates unique constraint "ticket_comments_pkey"');
SQL
