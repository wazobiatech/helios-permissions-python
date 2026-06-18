"""Logger protocol — minimal contract the SDK uses for diagnostics.

We don't depend on a specific logging library. The caller injects any
logger that has the standard ``.debug``/``.info``/``.warn``/``.error``
shape. stdlib ``logging.Logger`` and FastAPI's ``logger`` both satisfy
this out of the box.
"""

from __future__ import annotations

from typing import Any, Protocol


class Logger(Protocol):
    """Minimal logger protocol — debug/info/warn/error take any payload."""

    def debug(self, obj: dict[str, Any] | str, msg: str | None = None) -> None: ...
    def info(self, obj: dict[str, Any] | str, msg: str | None = None) -> None: ...
    def warn(self, obj: dict[str, Any] | str, msg: str | None = None) -> None: ...
    def error(self, obj: dict[str, Any] | str, msg: str | None = None) -> None: ...


class _SilentLogger:
    """Silent logger — for tests and the SDK's own internal use.

    Replace with a real logger in production via the factory option.
    """

    def debug(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        return None

    def info(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        return None

    def warn(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        return None

    def error(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        return None


silent_logger: Logger = _SilentLogger()


class _ConsoleLogger:
    """Console-based logger — for local dev / scripts."""

    def _emit(self, level: str, obj: dict[str, Any] | str, msg: str | None) -> None:
        import json
        import sys

        payload: dict[str, Any] = {"level": level}
        if isinstance(obj, dict):
            payload.update(obj)
        else:
            payload["obj"] = obj
        if msg is not None:
            payload["msg"] = msg
        print(json.dumps(payload), file=sys.stderr)

    def debug(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        self._emit("debug", obj, msg)

    def info(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        self._emit("info", obj, msg)

    def warn(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        self._emit("warn", obj, msg)

    def error(self, obj: dict[str, Any] | str, msg: str | None = None) -> None:
        self._emit("error", obj, msg)


console_logger: Logger = _ConsoleLogger()
