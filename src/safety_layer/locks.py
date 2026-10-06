    def _init_db(self) -> None:
        with self._connect() as connection:
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(approvals)").fetchall()}
            if not columns:
                connection.execute(
                    """
                    CREATE TABLE approvals (
                        approval_id TEXT PRIMARY KEY,
                        action TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        approver TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        state_hash TEXT,
                        consumed_at TEXT
                    )
                    """
                )
            elif "consumed_at" not in columns:
                connection.execute("ALTER TABLE approvals ADD COLUMN consumed_at TEXT")
