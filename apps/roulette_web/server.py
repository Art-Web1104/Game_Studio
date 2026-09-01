"""Loopback-only HTTP transport for the R4 roulette playable slice.

    python -m apps.roulette_web.server --port 8765

This module is a transport and nothing more. It parses a request, refuses everything it
cannot safely accept, and hands one whole decision to
:class:`~apps.roulette_web.table.RouletteTable`. No rule, payout or balance is computed
here, so there is no second implementation of the game to drift out of step with the first.

Refusals are the interesting part
---------------------------------
A local prototype is still reachable from every process on the machine, so the transport
fails closed rather than open:

* **Binding.** Only loopback. A hostname that resolves off-loopback is refused at start-up
  instead of being bound and regretted, and the default is ``127.0.0.1`` rather than ``''``.
* **Size.** ``Content-Length`` is required, capped by :data:`MAX_BODY_BYTES`, and checked
  *before* the body is read, so an oversized request costs a header parse and not memory.
  Chunked bodies are refused because a length that is not declared cannot be pre-checked.
* **Shape.** A body must be a JSON object. Anything that carries a server-authoritative
  field -- a pocket, a payout, a balance -- is rejected outright rather than filtered.
* **Errors.** Every failure is a JSON object with a stable code. Tracebacks, filesystem
  paths and database messages never reach a response body; unexpected exceptions become a
  flat ``INTERNAL_ERROR``.
* **Static files.** Served from one directory, resolved and confirmed to still be inside
  it after resolution, with an extension allowlist and fixed content types.

There is no login, no cookie, no account, no personal data and no outbound request. The
only state is the table's own database, which lives outside the repository by default.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from studio_core.durable_state import DurableRoundStore, DurableStateError

from .table import (
    NOTICE,
    RouletteTable,
    TableConfig,
    TableError,
    default_database_path,
    prohibited_client_fields,
)

__all__ = [
    "ALLOWED_STATIC_SUFFIXES",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "LOOPBACK_HOSTS",
    "MAX_BODY_BYTES",
    "ROUTES",
    "SECURITY_HEADERS",
    "STATIC_ROOT",
    "SliceHTTPServer",
    "build_handler",
    "create_server",
    "main",
    "open_table",
]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

#: Hostnames the server is willing to bind. A slice that holds authoritative balances has
#: no reason to be reachable from another machine, and "it was only meant for localhost" is
#: not a control.
LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost", "ip6-localhost"})

#: Generous for a bet, far too small to be worth sending as a denial-of-service payload.
MAX_BODY_BYTES = 8 * 1024

STATIC_ROOT = Path(__file__).resolve().parent / "static"

#: Extension allowlist and the exact content type each is served as. Serving a type the
#: browser sniffs is how a static directory becomes an execution surface.
ALLOWED_STATIC_SUFFIXES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json",
}

#: The client is served entirely from this origin and talks only to it, so the policy can
#: be restrictive without a workaround: no remote origin, no framing, no referrer.
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()"),
    ("Cache-Control", "no-store"),
)

#: Path to (method, table command). The table method takes ``(request_id, payload)`` for a
#: bet and ``(request_id)`` for the rest; :func:`build_handler` knows which is which by
#: consulting this table rather than by string-matching the path.
ROUTES: dict[str, str] = {
    "/api/state": "GET",
    "/api/bets": "POST",
    "/api/spin": "POST",
    "/api/new-round": "POST",
}


class SliceHTTPServer(ThreadingHTTPServer):
    """Threaded loopback server holding the single authoritative table."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: Any, table: RouletteTable) -> None:
        self.table = table
        super().__init__(address, handler)


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------


def _assert_loopback(host: str) -> str:
    """Return ``host`` if every address it resolves to is loopback, else refuse."""

    if host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"{host!r} is not a loopback host; this slice binds only {sorted(LOOPBACK_HOSTS)}"
        )
    for family, _, _, _, address in socket.getaddrinfo(host, None):
        literal = address[0]
        try:
            if not _is_loopback_literal(family, literal):
                raise ValueError(f"{host!r} resolves to the non-loopback address {literal!r}")
        except OSError:
            raise ValueError(f"{host!r} could not be resolved to a loopback address") from None
    return host


def _is_loopback_literal(family: int, literal: str) -> bool:
    import ipaddress

    return ipaddress.ip_address(literal.split("%", 1)[0]).is_loopback and family in (
        socket.AF_INET,
        socket.AF_INET6,
    )


def open_table(
    database: str | os.PathLike[str] | None = None,
    *,
    config: TableConfig | None = None,
    clock: Callable[[], str] | None = None,
    **store_options: Any,
) -> tuple[DurableRoundStore, RouletteTable]:
    """Open the durable store and the table over it, creating the parent directory.

    ``DurableRoundStore`` insists the parent directory already exists so a typo cannot
    quietly create a database somewhere unexpected. That is the right rule for the store
    and the wrong error for a first launch, so the launcher creates its own directory --
    and only its own -- before handing the path over.
    """

    path = Path(str(database) if database is not None else default_database_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    options: dict[str, Any] = {"namespace": "R4WEB"}
    if clock is not None:
        options["clock"] = clock
    options.update(store_options)
    store = DurableRoundStore(path, **options)
    try:
        table = RouletteTable(store, config=config, clock=clock)
    except BaseException:
        store.close()
        raise
    return store, table


def create_server(
    table: RouletteTable,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    quiet: bool = True,
) -> SliceHTTPServer:
    """Return a bound, unstarted server. ``port=0`` lets the OS pick a free port."""

    _assert_loopback(host)
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer in 0..65535")
    return SliceHTTPServer((host, port), build_handler(quiet=quiet), table)


# ---------------------------------------------------------------------------------------
# handler
# ---------------------------------------------------------------------------------------


def build_handler(*, quiet: bool = True) -> type[BaseHTTPRequestHandler]:
    """Return the request handler class, closed over the logging preference."""

    class SliceRequestHandler(BaseHTTPRequestHandler):
        server_version = "TsStudioRouletteSlice"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # -- logging ---------------------------------------------------------------------

        def log_message(self, fmt: str, *args: Any) -> None:
            if quiet:
                return
            sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

        def log_error(self, fmt: str, *args: Any) -> None:
            self.log_message(fmt, *args)

        # -- responses -------------------------------------------------------------------

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in SECURITY_HEADERS:
                self.send_header(name, value)
            # A keep-alive connection after a refusal would leave an unread body in the
            # socket and desynchronise the next request on it, so a refusal that set
            # ``close_connection`` says so in the header rather than only in the flag.
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            if getattr(self, "command", None) != "HEAD":
                self.wfile.write(body)

        def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
            body = dict(payload)
            body.setdefault("notice", dict(NOTICE))
            encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self._send(status, encoded, "application/json; charset=utf-8")

        def _send_error_json(self, status: int, code: str, message: str) -> None:
            self._send_json(status, {"error": {"code": code, "message": message}})

        # ``BaseHTTPRequestHandler`` answers its own protocol errors with an HTML page that
        # names the server and the failing request line. Overriding it keeps every response
        # from this process in one JSON shape with no internal detail in it.
        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            try:
                label = HTTPStatus(code).name
            except ValueError:
                label = "REQUEST_REJECTED"
            self.close_connection = True
            try:
                self._send_error_json(code, label, "the request was refused")
            except Exception:  # noqa: BLE001 - the connection is already going away
                pass

        # -- request parsing -------------------------------------------------------------

        def _path(self) -> str:
            from urllib.parse import unquote, urlsplit

            return unquote(urlsplit(self.path).path)

        def _read_body(self) -> Mapping[str, Any]:
            if self.headers.get("Transfer-Encoding"):
                raise TableError(
                    "LENGTH_REQUIRED",
                    "a declared Content-Length is required",
                    status=HTTPStatus.LENGTH_REQUIRED,
                )
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise TableError(
                    "LENGTH_REQUIRED",
                    "a declared Content-Length is required",
                    status=HTTPStatus.LENGTH_REQUIRED,
                )
            try:
                length = int(raw_length)
            except ValueError:
                raise TableError("BAD_REQUEST", "Content-Length is not an integer") from None
            if length < 0:
                raise TableError("BAD_REQUEST", "Content-Length is negative")
            if length > MAX_BODY_BYTES:
                raise TableError(
                    "PAYLOAD_TOO_LARGE",
                    f"the request body may not exceed {MAX_BODY_BYTES} bytes",
                    status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
            raw = self.rfile.read(length) if length else b""
            if len(raw) != length:
                raise TableError("BAD_REQUEST", "the request body was shorter than its Content-Length")
            try:
                payload = json.loads(raw.decode("utf-8") or "{}", parse_float=_refuse_float)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise TableError("BAD_JSON", "the request body is not valid UTF-8 JSON") from None
            except ValueError as exc:
                raise TableError("BAD_JSON", str(exc)) from None
            if not isinstance(payload, dict):
                raise TableError("BAD_JSON", "the request body must be a JSON object")
            leaking = prohibited_client_fields(payload)
            if leaking:
                raise TableError(
                    "CLIENT_AUTHORITY_DENIED",
                    "the server decides these values; remove: " + ", ".join(leaking),
                )
            return payload

        # -- dispatch --------------------------------------------------------------------

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_HEAD(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_PUT(self) -> None:
            self._reject_method()

        def do_DELETE(self) -> None:
            self._reject_method()

        def do_PATCH(self) -> None:
            self._reject_method()

        def do_OPTIONS(self) -> None:
            self._reject_method()

        def _reject_method(self) -> None:
            self._send_error_json(
                HTTPStatus.METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED", "this method is not accepted"
            )

        def _dispatch(self, method: str) -> None:
            path = self._path()
            try:
                if path in ROUTES:
                    if ROUTES[path] != method:
                        self._reject_method()
                        return
                    self._handle_api(path, method)
                    return
                self._serve_static(path)
            except TableError as refusal:
                # A refusal may have happened before the body was read; leaving the unread
                # bytes in a kept-alive socket would corrupt the next request framed on it.
                self.close_connection = True
                self._send_error_json(int(refusal.status), refusal.code, refusal.message)
            except (DurableStateError, ValueError):
                # A boundary refusal or a shape error. The code is useful, the message may
                # name a file or a column, so only the code crosses the wire.
                self.close_connection = True
                self._send_error_json(
                    HTTPStatus.CONFLICT, "REQUEST_REFUSED", "the request was refused by the server"
                )
            except Exception:  # noqa: BLE001 - nothing internal may reach the client
                self.close_connection = True
                self._send_error_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "the request could not be completed"
                )

        def _handle_api(self, path: str, method: str) -> None:
            table: RouletteTable = self.server.table  # type: ignore[attr-defined]
            if path == "/api/state":
                self._send_json(HTTPStatus.OK, {"state": table.state()})
                return
            payload = self._read_body()
            request_id = payload.get("request_id")
            if path == "/api/bets":
                unexpected = sorted(set(payload) - {"request_id", "bet"})
                if unexpected:
                    raise TableError("BAD_REQUEST", f"unexpected fields: {', '.join(unexpected)}")
                result = table.place_bet(request_id, payload.get("bet", {}))
            elif path == "/api/spin":
                unexpected = sorted(set(payload) - {"request_id"})
                if unexpected:
                    raise TableError("BAD_REQUEST", f"unexpected fields: {', '.join(unexpected)}")
                result = table.spin(request_id)
            else:
                unexpected = sorted(set(payload) - {"request_id"})
                if unexpected:
                    raise TableError("BAD_REQUEST", f"unexpected fields: {', '.join(unexpected)}")
                result = table.new_round(request_id)
            self._send_json(HTTPStatus.OK, result)

        # -- static ----------------------------------------------------------------------

        def _serve_static(self, path: str) -> None:
            """Serve one allowlisted file from :data:`STATIC_ROOT`, or refuse.

            The traversal defence is containment after resolution, not a scan for ``..``:
            a blocklist has to anticipate every spelling, while ``resolve()`` collapses
            them all and ``is_relative_to`` then answers the only question that matters --
            is the file the caller named actually inside the directory we publish? That
            also covers a symlink pointing out of the tree, which no amount of string
            inspection would catch.
            """

            if path in ("", "/"):
                path = "/index.html"
            relative = path.lstrip("/")
            if not relative or relative.endswith("/"):
                raise TableError("NOT_FOUND", "no such resource", status=HTTPStatus.NOT_FOUND)
            if "\x00" in relative or relative.startswith("."):
                raise TableError("NOT_FOUND", "no such resource", status=HTTPStatus.NOT_FOUND)

            root = STATIC_ROOT.resolve()
            candidate = (root / relative).resolve()
            if candidate != root and not candidate.is_relative_to(root):
                raise TableError("NOT_FOUND", "no such resource", status=HTTPStatus.NOT_FOUND)
            content_type = ALLOWED_STATIC_SUFFIXES.get(candidate.suffix.lower())
            if content_type is None or not candidate.is_file():
                raise TableError("NOT_FOUND", "no such resource", status=HTTPStatus.NOT_FOUND)
            self._send(HTTPStatus.OK, candidate.read_bytes(), content_type)

    return SliceRequestHandler


def _refuse_float(text: str) -> float:
    """Refuse a JSON number with a fractional part anywhere in a request.

    Currency is integer minimum units everywhere in this system. Accepting a float and
    rounding it later is how a stake of ``1.5`` becomes an argument about which side of the
    boundary the rounding happened on, so it never gets past the parser.
    """

    raise ValueError(f"floating-point values are not accepted: {text!r}")


# ---------------------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------------------


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m apps.roulette_web.server",
        description="Internal prototype roulette slice. Virtual chips only, no cash value.",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="loopback host to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port (default 8765)")
    parser.add_argument(
        "--db",
        default=None,
        help="runtime SQLite path; defaults outside the repository, or $ROULETTE_WEB_DB",
    )
    parser.add_argument("--verbose", action="store_true", help="log one line per request")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        _assert_loopback(args.host)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    store, table = open_table(args.db)
    try:
        server = create_server(table, host=args.host, port=args.port, quiet=not args.verbose)
    except BaseException:
        store.close()
        raise

    host, port = server.server_address[0], server.server_address[1]
    sys.stdout.write(
        f"{NOTICE['text_en']}\n{NOTICE['text_ko']}\n"
        f"serving http://{host}:{port}/  (loopback only, press Ctrl+C to stop)\n"
    )
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stdout.write("\nstopped\n")
    finally:
        server.shutdown()
        server.server_close()
        store.close()
    return 0


def serve_in_background(server: SliceHTTPServer) -> threading.Thread:
    """Run ``server`` on a daemon thread. Used by tests that talk real HTTP to it."""

    thread = threading.Thread(target=server.serve_forever, name="roulette-slice", daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    raise SystemExit(main())
