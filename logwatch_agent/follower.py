from __future__ import annotations

import os
from pathlib import Path

from .state import StateStore


class FileFollower:
    """Poll an appended text file, resuming from the last complete line."""

    def __init__(self, path: Path, state: StateStore) -> None:
        self.path = path
        self.state = state
        self._pending_cursor: tuple[str, int] | None = None

    @staticmethod
    def _file_id(stat: os.stat_result) -> str:
        return f"{stat.st_dev}:{stat.st_ino}"

    def read_new_lines(self) -> list[str]:
        stat = self.path.stat()
        file_id = self._file_id(stat)
        cursor = self.state.load_cursor(self.path)
        offset = cursor[1] if cursor and cursor[0] == file_id else 0
        if stat.st_size < offset:
            offset = 0

        lines: list[str] = []
        with self.path.open("rb") as stream:
            stream.seek(offset)
            while True:
                line_start = stream.tell()
                raw = stream.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    stream.seek(line_start)
                    break
                lines.append(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
                offset = stream.tell()

        self._pending_cursor = (file_id, offset)
        return lines

    def commit(self) -> None:
        """Persist the cursor after the caller has processed the returned lines."""
        if self._pending_cursor is not None:
            file_id, offset = self._pending_cursor
            self.state.save_cursor(self.path, file_id, offset)
            self._pending_cursor = None
