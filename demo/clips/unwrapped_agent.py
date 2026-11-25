"""A small agent with one tool wrapped by the checkpoint and one that is not.
`agent-gateway check --app unwrapped_agent.py` should find the second one."""
import psycopg

from agent_action_gateway import session


def run_sql(sql: str) -> list:
    with psycopg.connect("postgresql://demo@postgres/staging") as conn:
        return conn.execute(sql).fetchall()


def drop_table(name: str) -> None:
    with psycopg.connect("postgresql://demo@postgres/staging") as conn:
        conn.execute(f"DROP TABLE {name}")


with session(environment="staging") as ctx:
    safe_sql = ctx.tool(run_sql, action="db.run_sql", risk="destructive")
    safe_sql(sql="SELECT 1")
    drop_table("ticket_comments")   # called directly: skips every check
