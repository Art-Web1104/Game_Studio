"""R4-UI-0006 Phase B2: static client tests for the roulette playable slice.

The client is HTML, CSS and JavaScript with no build step and no runtime available in this
environment to execute it, so these tests assert the two things that can be checked without
a browser and that actually decide whether the acceptance criteria hold:

* **Delivery** -- over a real loopback socket, is each asset served from the one static
  directory with a fixed content type, the security headers, and a traversal defence that
  survives every spelling of ``..``?
* **Content** -- does the markup carry the disclosure, the accessibility affordances and the
  Content-Security-Policy discipline the server's own policy demands, does the stylesheet
  answer both a narrow viewport and ``prefers-reduced-motion``, and is the script free of
  the things a client must never contain: a source of randomness, a payout table, payout
  arithmetic, a balance it computes, or a request to anywhere but this origin?

The absence checks are the load-bearing ones. A client that quietly grew its own idea of
what a bet pays would still render perfectly, and only a test that looks for the arithmetic
would notice.
"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest
from html.parser import HTMLParser

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from apps.roulette_web.server import (  # noqa: E402
    ALLOWED_STATIC_SUFFIXES,
    ROUTES,
    SECURITY_HEADERS,
    STATIC_ROOT,
)
from studio_core.roulette import load_r1_rules  # noqa: E402
from test_roulette_web_server import HttpTestCase  # noqa: E402

INDEX = STATIC_ROOT / "index.html"
STYLES = STATIC_ROOT / "styles.css"
SCRIPT = STATIC_ROOT / "app.js"


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------------
# markup parsing
# ---------------------------------------------------------------------------------------


class Markup(HTMLParser):
    """Collects what the accessibility and CSP assertions need from one HTML document.

    A regular expression over markup answers the wrong question often enough to be worth
    avoiding: ``style`` inside a comment is not an inline style, and ``<button>`` matched by
    a pattern has no text content. The parser gives elements, their attributes and the text
    that falls inside each button, which is what is actually being asserted.
    """

    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.script_bodies: list[str] = []
        self.buttons: list[tuple[dict[str, str], str]] = []
        self._button_stack: list[list[str]] = []
        self._in_script = False
        self.feed(source)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: (value or "") for name, value in attrs}
        self.elements.append((tag, attributes))
        if tag == "script":
            self._in_script = True
        if tag == "button":
            self._button_stack.append([])
            self.buttons.append((attributes, ""))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, {name: (value or "") for name, value in attrs}))

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False
        if tag == "button" and self._button_stack:
            text = " ".join(self._button_stack.pop()).strip()
            for index in range(len(self.buttons) - 1, -1, -1):
                if self.buttons[index][1] == "":
                    self.buttons[index] = (self.buttons[index][0], text)
                    break

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.script_bodies.append(data)
        for frame in self._button_stack:
            if data.strip():
                frame.append(data.strip())

    def named(self, tag: str) -> list[dict[str, str]]:
        return [attrs for name, attrs in self.elements if name == tag]

    def with_attribute(self, name: str) -> list[tuple[str, dict[str, str]]]:
        return [(tag, attrs) for tag, attrs in self.elements if name in attrs]


def strip_js_noise(source: str) -> str:
    """Return ``source`` with comments and string literals blanked out.

    Comments are where the words "random" and "payout" legitimately appear in this client,
    so a scan that did not remove them would only ever find its own documentation. String
    literals go too, since Korean labels contain digits that would otherwise look like a
    payout table. There is no regular expression literal in the client, so ``/`` is always
    division here and needs no special case.
    """

    out: list[str] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        pair = source[index : index + 2]
        if pair == "//":
            end = source.find("\n", index)
            index = length if end == -1 else end
        elif pair == "/*":
            end = source.find("*/", index + 2)
            index = length if end == -1 else end + 2
        elif char in "\"'`":
            quote = char
            index += 1
            while index < length and source[index] != quote:
                index += 2 if source[index] == "\\" else 1
            index += 1
            out.append('""')
        else:
            out.append(char)
            index += 1
    return "".join(out)


def unbalanced_brackets(source: str) -> str | None:
    """Return a description of the first bracket that does not close, or ``None``.

    Not a parser, and not trying to be one. Without a JavaScript runtime in this
    environment the cheapest real signal that the file is structurally intact is that its
    braces, parentheses and brackets nest correctly once comments and strings are gone.
    """

    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for char in strip_js_noise(source):
        if char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                return f"unexpected {char!r}"
    return f"unclosed {stack[-1]!r}" if stack else None


# ---------------------------------------------------------------------------------------
# delivery
# ---------------------------------------------------------------------------------------


class StaticDeliveryTests(HttpTestCase):
    def test_every_client_asset_is_served_with_its_fixed_content_type(self) -> None:
        expected = {
            "/": "text/html; charset=utf-8",
            "/index.html": "text/html; charset=utf-8",
            "/styles.css": "text/css; charset=utf-8",
            "/app.js": "text/javascript; charset=utf-8",
        }
        for path, content_type in expected.items():
            response, body = self.request("GET", path)
            self.assertEqual(response.status, 200, path)
            self.assertEqual(response.getheader("Content-Type"), content_type, path)
            self.assertEqual(int(response.getheader("Content-Length")), len(body), path)
            self.assertTrue(body, path)

    def test_every_client_asset_carries_the_security_headers(self) -> None:
        for path in ("/", "/styles.css", "/app.js"):
            response, _ = self.request("GET", path)
            for name, value in SECURITY_HEADERS:
                self.assertEqual(response.getheader(name), value, f"{path} {name}")

    def test_the_content_security_policy_forbids_inline_and_remote_code(self) -> None:
        response, _ = self.request("GET", "/")
        policy = response.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", policy)
        self.assertIn("script-src 'self'", policy)
        self.assertIn("style-src 'self'", policy)
        self.assertNotIn("unsafe-inline", policy)
        self.assertNotIn("unsafe-eval", policy)

    def test_a_head_request_returns_the_headers_without_a_body(self) -> None:
        response, body = self.request("HEAD", "/app.js")
        self.assertEqual(response.status, 200)
        self.assertEqual(body, b"")
        self.assertGreater(int(response.getheader("Content-Length")), 0)

    def test_client_asset_path_traversal_spellings_are_all_refused(self) -> None:
        traversals = (
            "/../CLAUDE.md",
            "/styles.css/../../../CLAUDE.md",
            "/app.js/../../table.py",
            "/%2e%2e/%2e%2e/AGENTS.md",
            "/..%2f..%2fAGENTS.md",
            "/....//styles.css/../../server.py",
            "/static/app.js",
            "/./../table.py",
        )
        for path in traversals:
            response, body = self.request("GET", path)
            self.assertEqual(response.status, 404, path)
            text = body.decode("utf-8", "replace")
            self.assertNotIn("Operating Contract", text, path)
            self.assertNotIn("RouletteTable", text, path)

    def test_an_asset_that_does_not_exist_is_a_json_404_with_no_internal_detail(self) -> None:
        response, payload = self.json_request("GET", "/favicon.ico")
        self.assertEqual(response.status, 404)
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")
        self.assertIn("notice", payload)
        for leak in ("Traceback", "static", ".py", "sqlite", str(STATIC_ROOT)):
            self.assertNotIn(leak, payload["error"]["message"])

    def test_the_static_directory_holds_only_allowlisted_client_assets(self) -> None:
        served = sorted(p.name for p in STATIC_ROOT.iterdir() if p.is_file())
        self.assertEqual(served, ["app.js", "index.html", "styles.css"])
        for name in served:
            self.assertIn(pathlib.Path(name).suffix, ALLOWED_STATIC_SUFFIXES, name)

    def test_the_served_index_is_the_file_on_disk_and_links_only_local_assets(self) -> None:
        # Raw bytes on both sides. The handler answers with ``candidate.read_bytes()``, so the
        # only like-for-like comparison is against ``read_bytes()`` here too: ``read_text``
        # opens in universal-newlines mode and silently folds CRLF to LF, which turns a
        # Windows ``core.autocrlf`` checkout of an LF-committed file into a false mismatch.
        # Comparing the bytes is the stronger claim as well -- it is the one that would still
        # notice a line terminator the server had rewritten.
        _, body = self.request("GET", "/")
        self.assertEqual(body, INDEX.read_bytes())
        text = body.decode("utf-8")
        self.assertIn('href="/styles.css"', text)
        self.assertIn('src="/app.js"', text)


# ---------------------------------------------------------------------------------------
# disclosure
# ---------------------------------------------------------------------------------------


class DisclosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = read(INDEX)
        self.js = read(SCRIPT)

    def test_the_internal_prototype_framing_is_stated_in_korean_and_english(self) -> None:
        for phrase in (
            "INTERNAL PROTOTYPE",
            "내부 프로토타입",
            "가상 칩",
            "현금 가치 없음",
            "Internal prototype. Virtual chips only. No cash value.",
            "내부 프로토타입입니다. 가상 칩만 사용하며 현금 가치가 없습니다.",
        ):
            self.assertIn(phrase, self.html, phrase)

    def test_the_disclosure_is_in_the_title_and_at_the_top_of_the_document(self) -> None:
        title = re.search(r"<title>(.*?)</title>", self.html, re.S)
        self.assertIsNotNone(title)
        self.assertIn("내부 프로토타입", title.group(1))
        self.assertIn("현금 가치 없음", title.group(1))
        body = self.html.index("<body")
        banner = self.html.index("INTERNAL PROTOTYPE")
        main = self.html.index("<main")
        self.assertLess(body, banner, "the disclosure must precede the interface")
        self.assertLess(banner, main, "the disclosure must precede the interface")

    def test_no_purchase_exchange_or_release_path_is_offered_anywhere_in_the_client(self) -> None:
        forbidden = (
            "충전",
            "결제",
            "환전",
            "인출",
            "실물 보상",
            "구매",
            "상점",
            "출시",
            "purchase",
            "payment",
            "deposit",
            "withdraw",
            "cash out",
            "checkout",
            "top-up",
        )
        for source, label in ((self.html, "index.html"), (self.js, "app.js"), (read(STYLES), "styles.css")):
            lowered = source.lower()
            for term in forbidden:
                self.assertNotIn(term.lower(), lowered, f"{label} names {term!r}")

    def test_the_client_collects_no_credential_or_personal_data(self) -> None:
        markup = Markup(self.html)
        self.assertEqual(markup.named("form"), [], "the client has no form to submit anywhere")
        for attrs in markup.named("input"):
            self.assertIn(attrs.get("type"), {"radio"}, attrs)
            self.assertNotIn("autocomplete", attrs)
        for term in ("password", "email", "signin", "sign-in", "login", "account_id"):
            self.assertNotIn(term, self.js.lower(), term)

    def test_the_footer_restates_the_notice_the_server_sends(self) -> None:
        self.assertIn('id="server-notice"', self.html)
        self.assertIn("notice.text_ko", self.js, "the footer notice is refreshed from the server")


# ---------------------------------------------------------------------------------------
# accessibility and CSP discipline in the markup
# ---------------------------------------------------------------------------------------


class MarkupAccessibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = read(INDEX)
        self.markup = Markup(self.html)

    def test_the_document_declares_korean_and_a_responsive_viewport(self) -> None:
        self.assertRegex(self.html, r"<html[^>]*\blang=\"ko\"")
        viewports = [
            attrs for attrs in self.markup.named("meta") if attrs.get("name") == "viewport"
        ]
        self.assertEqual(len(viewports), 1)
        self.assertIn("width=device-width", viewports[0]["content"])
        self.assertIn("initial-scale=1", viewports[0]["content"])
        # A viewport that forbids zooming fails the same criterion it looks like it serves.
        self.assertNotIn("user-scalable=no", viewports[0]["content"])
        self.assertNotIn("maximum-scale", viewports[0]["content"])

    def test_the_page_has_one_heading_hierarchy_and_landmark_regions(self) -> None:
        self.assertEqual(len(self.markup.named("h1")), 1)
        self.assertTrue(self.markup.named("main"))
        self.assertTrue(self.markup.named("header"))
        self.assertTrue(self.markup.named("footer"))
        for attrs in self.markup.named("section"):
            self.assertTrue(
                attrs.get("aria-labelledby") or attrs.get("aria-label"),
                f"an unnamed section is an unnavigable section: {attrs}",
            )

    def test_every_live_region_needed_for_round_state_is_present(self) -> None:
        roles = [attrs.get("role") for _, attrs in self.markup.elements if attrs.get("role")]
        self.assertIn("status", roles, "round state needs a polite live region")
        self.assertIn("alert", roles, "a refusal must be announced without being polled")
        live = [attrs for _, attrs in self.markup.with_attribute("aria-live")]
        self.assertGreaterEqual(len(live), 2)
        self.assertTrue(any(attrs.get("aria-live") == "polite" for attrs in live))
        self.assertTrue(any(attrs.get("aria-atomic") == "true" for attrs in live))

    def test_every_control_is_a_real_button_or_input_with_an_accessible_name(self) -> None:
        self.assertTrue(self.markup.buttons)
        for attrs, text in self.markup.buttons:
            name = text or attrs.get("aria-label", "")
            self.assertTrue(name.strip(), f"a button with no accessible name: {attrs}")
            self.assertEqual(attrs.get("type"), "button", attrs)
        # Nothing may be made clickable without also being focusable and operable by keyboard.
        for tag, attrs in self.markup.with_attribute("onclick"):
            self.fail(f"<{tag}> carries an inline handler: {attrs}")
        for tag, attrs in self.markup.elements:
            if tag in {"div", "span", "li", "p"} and attrs.get("role") in {"button", "link"}:
                self.fail(f"<{tag}> impersonates a control instead of being one")

    def test_a_skip_link_and_a_noscript_fallback_are_provided(self) -> None:
        self.assertIn("skip-link", self.html)
        self.assertTrue(self.markup.named("noscript"))
        noscript = self.html[self.html.index("<noscript>") : self.html.index("</noscript>")]
        self.assertIn("가상 칩", noscript)
        self.assertIn("/api/state", noscript)

    def test_the_markup_contains_nothing_the_content_security_policy_would_refuse(self) -> None:
        self.assertEqual(self.markup.script_bodies, [], "an inline script would be blocked")
        self.assertEqual(self.markup.named("style"), [], "an inline stylesheet would be blocked")
        for tag, attrs in self.markup.elements:
            self.assertNotIn("style", attrs, f"<{tag}> carries an inline style attribute")
            for name in attrs:
                self.assertFalse(name.startswith("on"), f"<{tag}> carries the {name} handler")
        for attrs in self.markup.named("script"):
            self.assertTrue(attrs.get("src", "").startswith("/"), attrs)
            self.assertIn("defer", attrs)

    def test_no_asset_is_requested_from_another_origin(self) -> None:
        for attribute in ("src", "href"):
            for tag, attrs in self.markup.with_attribute(attribute):
                value = attrs[attribute]
                self.assertTrue(
                    value.startswith("/") or value.startswith("#"),
                    f"<{tag} {attribute}={value!r}> is not served by this origin",
                )
        for scheme in ("http://", "https://", "//cdn", "data:font"):
            self.assertNotIn(scheme, self.html, scheme)

    def test_the_wheel_is_described_as_decoration_driven_by_the_server(self) -> None:
        svgs = self.markup.named("svg")
        self.assertEqual(len(svgs), 1)
        self.assertEqual(svgs[0].get("role"), "img")
        self.assertTrue(svgs[0].get("aria-labelledby"))
        self.assertIn("결과는 서버가 결정하며", self.html)


# ---------------------------------------------------------------------------------------
# stylesheet
# ---------------------------------------------------------------------------------------


class StylesheetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.css = read(STYLES)

    def test_the_layout_is_mobile_first_and_widens_at_declared_breakpoints(self) -> None:
        breakpoints = re.findall(r"@media \(min-width: ([^)]+)\)", self.css)
        self.assertGreaterEqual(len(breakpoints), 2, "a phone and a desktop layout are required")
        self.assertNotIn("@media (max-width", self.css, "the base rules are the narrow ones")
        first_breakpoint = self.css.index("@media (min-width")
        self.assertIn(".board {", self.css[:first_breakpoint], "the board must lay out unaided")
        self.assertIn("grid-template-columns", self.css)

    def test_reduced_motion_is_honoured(self) -> None:
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.css)
        block_start = self.css.index("@media (prefers-reduced-motion: reduce)")
        block = self.css[block_start : block_start + 900]
        self.assertIn("animation-duration", block)
        self.assertIn("transition-duration", block)

    def test_keyboard_focus_is_always_visible(self) -> None:
        self.assertIn(":focus-visible", self.css)
        self.assertIn("outline:", self.css)
        self.assertNotIn("outline: none", self.css)
        self.assertNotIn("outline: 0", self.css)
        self.assertIn("@supports not selector(:focus-visible)", self.css)

    def test_a_screen_reader_only_class_exists_and_is_not_display_none(self) -> None:
        start = self.css.index(".visually-hidden")
        block = self.css[start : self.css.index("}", start)]
        self.assertNotIn("display: none", block)
        self.assertIn("clip-path", block)

    def test_the_stylesheet_loads_nothing_from_outside_this_origin(self) -> None:
        self.assertNotIn("@import", self.css)
        self.assertNotIn("@font-face", self.css)
        for scheme in ("url(http", "url('http", 'url("http', "//fonts."):
            self.assertNotIn(scheme, self.css, scheme)


# ---------------------------------------------------------------------------------------
# the script: what it must not contain
# ---------------------------------------------------------------------------------------


class ClientAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.js = read(SCRIPT)
        self.code = strip_js_noise(self.js)
        self.rules = load_r1_rules()

    def test_the_script_is_structurally_intact(self) -> None:
        self.assertIsNone(unbalanced_brackets(self.js))
        self.assertIn('"use strict"', self.js)

    def test_the_client_holds_no_source_of_randomness(self) -> None:
        for source in (
            "Math.random",
            "getRandomValues",
            "randomUUID",
            "crypto",
            "Random",
            "seed",
        ):
            self.assertNotIn(source, self.code, f"the client must not carry {source}")

    def test_the_client_carries_no_payout_table(self) -> None:
        for bet_type, payout in self.rules["payouts"].items():
            pattern = re.compile(rf"[\"']?{bet_type}[\"']?\s*[:=]\s*{payout}\b")
            self.assertIsNone(
                pattern.search(self.code),
                f"the client appears to declare that {bet_type} pays {payout}",
            )

    def test_the_client_performs_no_payout_or_balance_arithmetic(self) -> None:
        forbidden = (
            r"stake\w*\s*\*",
            r"\*\s*stake\w*",
            r"payout\w*\s*\*",
            r"\*\s*payout\w*",
            r"balance\w*\s*[-+]\s*\w",
            r"\bwon\s*=[^=]",
            r"\bpocket\s*===",
        )
        for pattern in forbidden:
            self.assertIsNone(
                re.search(pattern, self.code),
                f"the client appears to compute an authoritative value: {pattern}",
            )
        for name in ("settleBet", "calculatePayout", "computeWin", "isWinner", "determineResult"):
            self.assertNotIn(name, self.code, name)

    def test_authoritative_values_are_read_from_the_server_response(self) -> None:
        for reference in (
            "payload.state",
            "payload.result",
            "result.pocket",
            "result.net_change_units",
            "result.total_return_units",
            "outcome.won",
            "outcome.payout_units",
            "state.balance_units",
            "state.recent_results",
        ):
            self.assertIn(reference, self.js, f"{reference} must come from the server")

    def test_the_board_is_built_from_the_pocket_list_the_server_publishes(self) -> None:
        self.assertIn("state.table.pockets", self.js)
        self.assertIn("state.table.red_numbers", self.js)
        self.assertIn("bet_selection_counts", self.js)

    def test_the_wheel_is_positioned_from_the_server_pocket_only(self) -> None:
        self.assertIn("spinWheelTo(payload.result.pocket)", self.js)
        self.assertIn("indexOf(pocket)", self.js)
        self.assertIn("prefersReducedMotion", self.js)


class ClientProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.js = read(SCRIPT)
        self.code = strip_js_noise(self.js)

    def test_the_client_talks_only_to_the_declared_routes_on_this_origin(self) -> None:
        called = set(re.findall(r"[\"'](/api/[A-Za-z0-9\-/]*)[\"']", self.js))
        self.assertTrue(called)
        self.assertLessEqual(called, set(ROUTES), f"unknown route: {called - set(ROUTES)}")
        urls = set(re.findall(r"https?://[^\s\"')]+", self.js))
        self.assertLessEqual(
            urls,
            {"http://www.w3.org/2000/svg"},
            "the only absolute URL permitted is the SVG namespace, which is not a request",
        )
        for api in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "navigator.send"):
            self.assertNotIn(api, self.code, api)

    def test_the_client_stores_nothing_and_evaluates_nothing(self) -> None:
        for api in ("localStorage", "sessionStorage", "indexedDB", "document.cookie", "eval("):
            self.assertNotIn(api, self.code, api)
        # Text is written as text, so a server string can never become markup.
        self.assertNotIn("innerHTML", self.code)
        self.assertNotIn("document.write", self.code)
        self.assertIn("textContent", self.code)

    def test_a_request_identifier_is_an_idempotency_key_from_a_counter(self) -> None:
        self.assertIn("requestCounter += 1", self.code)
        self.assertIn("request_id", self.js)
        # Held until the server answers, so a retry replays instead of repeating.
        self.assertIn("heldRequestId", self.code)
        self.assertIn("releaseRequestId", self.code)
        self.assertIn("REQUEST_ID_PATTERN", self.js)

    def test_a_second_click_cannot_start_a_second_request(self) -> None:
        self.assertIn("if (ui.busy)", self.code)
        self.assertIn("setBusy(true", self.code)
        self.assertIn("setBusy(false", self.code)
        self.assertIn("aria-busy", self.js)
        self.assertIn("disabled", self.code)

    def test_a_failure_is_shown_with_a_retry_that_reuses_the_same_request(self) -> None:
        self.assertIn("showError", self.code)
        self.assertIn("retryAction", self.code)
        self.assertIn("NETWORK", self.code)
        # The identifier is only released once a response has been seen, which is what makes
        # the retry a replay rather than a second spin. Both positions are read from the file
        # as written, not from ``self.code``: ``strip_js_noise`` blanks string literals, so in
        # the stripped source the call is ``releaseRequestId("")`` and the route is gone
        # entirely -- an ordering assertion over two positions that no longer exist.
        release = self.js.index('releaseRequestId("spin")')
        spin_call = self.js.index("/api/spin")
        self.assertLess(spin_call, release)


if __name__ == "__main__":
    unittest.main()
