"""Transactional, versioned PostgreSQL/SQLite migrations.

v1 is the frozen schema baseline from SQLAlchemy models at initial release.
Every later structural change is an explicit migration, not create_all on an
existing database. Existing databases without a trustworthy version marker
are rejected rather than modified speculatively.
"""
from __future__ import annotations

from sqlalchemy import inspect, select, text

from .models import Base, SchemaVersion, WorkerStatus, engine


LATEST_VERSION = 3
MIGRATIONS = {
    2: [
        # A concurrent worker cannot open two active incidents for one scope.
        # Duplicate legacy records must be reconciled explicitly first.
        """CREATE UNIQUE INDEX IF NOT EXISTS uq_active_incident_scope
           ON incidents (team_id, service_id, environment_id)
           WHERE state <> 'resolved'""",
        """CREATE INDEX IF NOT EXISTS ix_outbox_pending
           ON outbox (id) WHERE processed_at IS NULL""",
        """CREATE INDEX IF NOT EXISTS ix_incident_unacked
           ON incidents (created_at) WHERE state = 'open'""",
    ],
    3: [],  # Worker status is created via its versioned SQLAlchemy Table DDL.
}


def _assert_unique_active_incidents(connection):
    duplicates = connection.execute(text(
        """SELECT team_id, service_id, environment_id, count(*) AS total
           FROM incidents WHERE state <> 'resolved'
           GROUP BY team_id, service_id, environment_id
           HAVING count(*) > 1 LIMIT 1"""
    )).first()
    if duplicates:
        raise RuntimeError(
            "Cannot upgrade: multiple active incidents for team/service/environment "
            f"{duplicates[0]}/{duplicates[1]}/{duplicates[2]}. Resolve duplicates "
            "manually with a backup before retrying."
        )


def migrate():
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            # Serialize concurrent migration calls across Compose processes.
            connection.execute(text("SELECT pg_advisory_xact_lock(139724, 200)"))
        tables = set(inspect(connection).get_table_names())
        if not tables:
            # Keep the original v1 baseline stable; v3 table is created only by v3.
            Base.metadata.create_all(connection, tables=[
                table for table in Base.metadata.sorted_tables
                if table.name != WorkerStatus.__tablename__
            ])
            connection.execute(SchemaVersion.__table__.insert().values(version=1))
            tables = set(inspect(connection).get_table_names())
        if "schema_version" not in tables:
            raise RuntimeError(
                "Unversioned database detected. Restore a backup or migrate it "
                "manually; refusing to guess the existing schema."
            )
        versions = set(connection.scalars(select(SchemaVersion.version)).all())
        if not versions or 1 not in versions or any(v > LATEST_VERSION for v in versions):
            raise RuntimeError(f"Unexpected schema versions: {sorted(versions)}")
        current = max(versions)
        if versions != set(range(1, current + 1)):
            raise RuntimeError(f"Gaps in schema history: {sorted(versions)}")
        for version in range(current + 1, LATEST_VERSION + 1):
            if version == 2:
                _assert_unique_active_incidents(connection)
            for statement in MIGRATIONS[version]:
                connection.execute(text(statement))
            if version == 3:
                WorkerStatus.__table__.create(connection, checkfirst=True)
            connection.execute(SchemaVersion.__table__.insert().values(version=version))
    return LATEST_VERSION
