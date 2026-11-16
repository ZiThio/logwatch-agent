from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .core import Alert


class StateStore:
    """Persists file cursors and emitted alert IDs in a local SQLite database."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path)
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS cursors (
                path TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                offset INTEGER NOT NULL
            )"""
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )"""
        )
        self._connection.commit()

    def load_cursor(self, path: Path) -> tuple[str, int] | None:
        row = self._connection.execute(
            "SELECT file_id, offset FROM cursors WHERE path = ?", (str(path.resolve()),)
        ).fetchone()
        return (str(row[0]), int(row[1])) if row else None

    def save_cursor(self, path: Path, file_id: str, offset: int) -> None:
        self._connection.execute(
            """INSERT INTO cursors(path, file_id, offset) VALUES(?, ?, ?)
               ON CONFLICT(path) DO UPDATE SET file_id=excluded.file_id, offset=excluded.offset""",
            (str(path.resolve()), file_id, offset),
        )
        self._connection.commit()

    def save_alert_once(self, alert: Alert) -> bool:
        cursor = self._connection.execute(
            "INSERT OR IGNORE INTO alerts(alert_id, payload) VALUES(?, ?)",
            (alert.alert_id, json.dumps(alert.to_dict(), ensure_ascii=False)),
        )
        self._connection.commit()
        return cursor.rowcount == 1

    def has_alert(self, alert_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return row is not None

    def close(self) -> None:
        self._connection.close()
