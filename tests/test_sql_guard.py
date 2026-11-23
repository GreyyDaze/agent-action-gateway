"""`is_read_only_sql`: only text that certainly just reads counts as a read."""

from __future__ import annotations

import unittest

from agent_action_gateway.guards.sql import is_read_only_sql

READS = [
    "SELECT * FROM users",
    "select id, name from users where id = 1;",
    "  SELECT count(*) FROM orders  ",
    "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent",
    "SHOW search_path",
    "EXPLAIN SELECT * FROM users",
    "EXPLAIN ANALYZE SELECT * FROM users",
    "VALUES (1), (2)",
    "TABLE users",
    "SELECT 1; SELECT 2",
    "SELECT CASE WHEN a > 1 THEN 'x' END, replace(name, 'a', 'b') FROM t",
    "SELECT 'DROP TABLE users' AS text",
    "SELECT $$ DELETE FROM users $$",
    "SELECT $tag$ it's DELETE $tag$",
    "SELECT \"delete\" FROM t",
    "SELECT 1 -- DROP TABLE users",
    "SELECT /* DELETE /* nested */ FROM x */ 1",
    "SELECT E'it\\'s fine'",
    "SELECT arr[1] FROM t",
    "SELECT * FROM t WHERE id = $1",
    "SELECT created_at, updated_at FROM t",
    # In E'...' the backslash escapes the quote, so all of this is one string.
    "SELECT E'\\'; DROP TABLE users; --'",
]

NOT_READS = [
    "",
    "   ",
    None,
    42,
    "DROP TABLE users",
    "drop table users",
    "DELETE FROM users",
    "UPDATE users SET name = 'x'",
    "INSERT INTO users VALUES (1)",
    "TRUNCATE users",
    "ALTER TABLE users DROP COLUMN email",
    "CREATE TABLE x (id int)",
    "GRANT ALL ON users TO bob",
    "SELECT 1; DROP TABLE users",
    "SELECT 1; DELETE FROM users",
    "WITH gone AS (DELETE FROM users RETURNING *) SELECT * FROM gone",
    "SELECT * INTO backup FROM users",
    "SELECT * FROM users FOR UPDATE",
    "SELECT * FROM users FOR SHARE",
    "EXPLAIN ANALYZE DELETE FROM users",
    "SELECT nextval('seq')",
    "SELECT pg_terminate_backend(123)",
    "SELECT set_config('role', 'admin', false)",
    "COPY users TO '/tmp/x'",
    "SET role admin",
    "CALL cleanup()",
    "DO $$ BEGIN DELETE FROM users; END $$",
    "BEGIN; SELECT 1; COMMIT",
    "VACUUM users",
    "SELECT 'unclosed",
    "SELECT \"unclosed",
    "SELECT $$ unclosed",
    "SELECT /* unclosed",
    "SELECT `x` FROM t",
    "SELECT 1 /* ok */; DROP /* hidden */ TABLE users",
    # A plain string keeps the backslash, so the string ends early and the
    # DROP is real (standard_conforming_strings on).
    "SELECT '\\'; DROP TABLE users; --'",
]


class ReadOnlySqlTest(unittest.TestCase):
    def test_reads(self) -> None:
        for sql in READS:
            with self.subTest(sql=sql):
                self.assertTrue(is_read_only_sql(sql))

    def test_not_reads(self) -> None:
        for sql in NOT_READS:
            with self.subTest(sql=sql):
                self.assertFalse(is_read_only_sql(sql))


if __name__ == "__main__":
    unittest.main()
