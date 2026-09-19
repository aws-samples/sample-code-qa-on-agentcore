"""Peer-address admission check (AppSec finding 608d4a22).

The bridge has no application auth, so as deployed the security group is the only control.
This check is the second, in-process enforcement point. These tests pin the two properties
that matter: the loopback health probe must keep working, and a public peer must be refused.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

IDX_DIR = Path(__file__).resolve().parent.parent
if str(IDX_DIR) not in sys.path:
    sys.path.insert(0, str(IDX_DIR))

import peer_guard  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("BRIDGE_ALLOW_ANY_PEER", raising=False)
    peer_guard._reported.clear()
    # Reset the cap flag too. Clearing only the set would leave a test that tripped the cap
    # silently suppressing every later test's rejection log, which looks like a dedup bug.
    peer_guard._report_cap_hit = False


@pytest.mark.parametrize(
    ("peer", "allowed"),
    [
        # Must pass — breaking any of these is a self-inflicted outage.
        ("127.0.0.1", True),      # the /health probe the deployed unit depends on
        ("::1", True),
        ("[::1]", True),
        ("10.0.3.17", True),      # AgentCore runtime over the VPC
        ("172.16.5.4", True),
        ("192.168.1.9", True),
        ("fd00::1", True),        # IPv6 ULA
        ("169.254.169.254", True),  # link-local
        ("::ffff:10.0.0.5", True),  # IPv4-mapped private address
        (None, True),             # no peer at all: in-process/unix transport
        # NOTE on range choice: `ipaddress.is_private` covers every special-purpose,
        # non-globally-routable block — which INCLUDES the documentation ranges
        # (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32). Those are therefore
        # ADMITTED by this check, so they cannot stand in for "a public peer" here. Use
        # genuinely globally-routable addresses instead.
        # Must be refused.
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("2606:4700:4700::1111", False),
        ("10.evil.com", False),   # NOT a private address: string-shape tests accept this
        ("localhost", False),     # a name, not an address — peers arrive as literals
        ("not-an-ip", False),
    ],
)
def test_is_local_peer_classifies_by_address(peer, allowed):
    assert peer_guard.is_local_peer(peer) is allowed


def test_allow_any_peer_opt_out_admits_a_public_peer(monkeypatch):
    assert peer_guard.peer_is_admissible("8.8.8.8") is False
    monkeypatch.setenv("BRIDGE_ALLOW_ANY_PEER", "1")
    # Read at call time, so an operator's unit-file edit takes effect without import games.
    assert peer_guard.peer_is_admissible("8.8.8.8") is True


def test_rejection_is_logged_once_per_peer(caplog):
    with caplog.at_level("WARNING"):
        peer_guard.log_rejection("8.8.8.8", "/mcp")
        peer_guard.log_rejection("8.8.8.8", "/mcp")
    # Once per peer: a scanner must not be able to turn this into a log-amplification channel.
    hits = [m for m in caplog.messages if "bridge_peer_rejected" in m]
    assert len(hits) == 1
    payload = json.loads(hits[0])
    assert payload["peer"] == "8.8.8.8"
    assert payload["path"] == "/mcp"


def test_peer_tracking_is_bounded_and_says_so_once(caplog):
    """The dedup set must not grow without limit while the guard is doing its job.

    The condition this control exists for — a security group or route table wider than intended —
    is also the condition under which many distinct peers reach the reject path. An unbounded set
    turns dedup into a memory leak on a long-lived bridge process precisely then.
    """
    with caplog.at_level("WARNING"):
        for i in range(peer_guard.MAX_REPORTED_PEERS + 50):
            # 8.x.x.x is globally routable, so every one of these is genuinely refused.
            peer_guard.log_rejection(f"8.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}", "/mcp")

    assert len(peer_guard._reported) == peer_guard.MAX_REPORTED_PEERS

    per_peer = [m for m in caplog.messages if "bridge_peer_rejected\"" in m]
    assert len(per_peer) == peer_guard.MAX_REPORTED_PEERS

    # The cap itself is announced exactly once — it is the actionable fact, and repeating it would
    # reintroduce the very log flood the cap is there to prevent.
    capped = [m for m in caplog.messages if "bridge_peer_rejected_log_capped" in m]
    assert len(capped) == 1
    assert json.loads(capped[0])["distinct_peers"] == peer_guard.MAX_REPORTED_PEERS


def test_enforcement_continues_after_the_log_cap_is_reached():
    """Reaching the log cap must silence logging only, never admission."""
    for i in range(peer_guard.MAX_REPORTED_PEERS + 10):
        peer_guard.log_rejection(f"8.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}", "/mcp")
    # A public peer is still refused after the cap; the cap governs the log, not the decision.
    assert peer_guard.peer_is_admissible("8.8.8.8") is False
    assert peer_guard.peer_is_admissible("127.0.0.1") is True


def test_http_scope_without_client_is_refused():
    """An HTTP scope with no identifiable peer must FAIL CLOSED.

    is_local_peer(None) is True, and that is right for a transport that has no address at all. But
    a real http scope reaching the middleware without `client` is an unidentifiable NETWORK peer,
    and waving it through inverts a control whose whole purpose is authorization by network
    position: any server or fronting layer that omits `client` would admit an external caller to
    the source-read handlers.
    """
    status, _body, called = _drive({"type": "http", "path": "/mcp"})
    assert status == 403
    assert called is False, "downstream handler must not run for an unidentifiable peer"
    # And with client explicitly empty rather than absent.
    status2, _b2, called2 = _drive({"type": "http", "path": "/mcp", "client": ()})
    assert status2 == 403
    assert called2 is False


def test_the_two_predicates_differ_exactly_on_an_unidentifiable_host():
    """The bare predicate and the http one agree everywhere except where the peer is absent.

    Stated as the absent CLASS, not as "the None case". The earlier version of this test said
    None and sampled no empty string, so it kept passing while `("", 0)` was being admitted —
    the test named the same too-narrow invariant the code implemented, which is why it could not
    catch it (found by automated review on revision 13).

    Pinning this keeps the deliberate difference deliberate in BOTH directions: 'simplifying' the
    middleware back to the bare predicate reopens the fail-open, and 'unifying' the bare
    predicate onto the http one breaks the in-process and unix-socket transports that
    legitimately have no address.

    One test rather than two: an earlier draft of this change added a second test asserting the
    same invariant from the is_local_peer side, which is the maintain-it-twice shape this whole
    review cycle keeps tripping over.
    """
    # The absent class — the bare predicate calls it local, the http one refuses it.
    for host in (None, ""):
        assert peer_guard.peer_is_admissible(host) is True, host
        assert peer_guard.is_local_peer(host) is True, host
        assert peer_guard.http_peer_is_admissible(host) is False, host
    # Everywhere else they must agree — including values that LOOK absent but are not falsy, and
    # so were never the ones at risk.
    for host in ("127.0.0.1", "10.0.3.17", "8.8.8.8", "not-an-ip", "::1", "  ", "[]", "unknown"):
        assert peer_guard.peer_is_admissible(host) == peer_guard.http_peer_is_admissible(host), host


def test_allow_any_peer_still_overrides_the_missing_host_refusal(monkeypatch):
    """The documented opt-out must remain a full opt-out, including for an absent client."""
    monkeypatch.setenv("BRIDGE_ALLOW_ANY_PEER", "1")
    assert peer_guard.http_peer_is_admissible(None) is True
    status, _body, called = _drive({"type": "http", "path": "/mcp"})
    assert status == 200
    assert called is True


async def _collect(middleware, scope):
    """Drive the middleware and return (status, body, downstream_called)."""
    sent: list[dict] = []
    called = {"downstream": False}

    async def app(_scope, _receive, _send):
        called["downstream"] = True
        await _send({"type": "http.response.start", "status": 200, "headers": []})
        await _send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request"}

    async def send(msg):
        sent.append(msg)

    middleware.app = app
    await middleware(scope, receive, send)
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body, called["downstream"]


def _drive(scope):
    """asyncio.run wrapper — this repo has no pytest-asyncio, and an @asyncio-marked test
    would be SKIPPED rather than run, which is indistinguishable from passing."""
    return asyncio.run(_collect(peer_guard.PeerGuardMiddleware(None), scope))


def test_middleware_admits_loopback_and_reaches_the_handler():
    status, body, downstream = _drive(
        {"type": "http", "path": "/health", "client": ("127.0.0.1", 51234)},
    )
    assert downstream is True
    assert status == 200
    assert body == b"ok"


def test_middleware_refuses_a_public_peer_before_the_handler_runs():
    status, body, downstream = _drive(
        {"type": "http", "path": "/mcp", "client": ("8.8.8.8", 4444)},
    )
    # The point of doing this in middleware: the source-read handlers never execute.
    assert downstream is False
    assert status == 403
    assert b"forbidden" in body


def test_middleware_ignores_a_forwarded_for_header():
    """A forwarding header is set by the caller, so trusting it would defeat the check."""
    status, _body, downstream = _drive({
        "type": "http", "path": "/mcp", "client": ("8.8.8.8", 4444),
        "headers": [(b"x-forwarded-for", b"127.0.0.1")],
    })
    assert downstream is False
    assert status == 403


def test_middleware_passes_non_http_scopes_through():
    mw = peer_guard.PeerGuardMiddleware(None)
    seen = {"type": None}

    async def app(scope, _receive, _send):
        seen["type"] = scope["type"]

    mw.app = app
    asyncio.run(mw({"type": "lifespan"}, None, None))
    assert seen["type"] == "lifespan"


# ── build_asgi_app attaches the guard, so a second entry point cannot forget it ──
#
# Raised by automated review on revision 12: the flock lives in build_bridge() while the peer
# check was inline in main(), so the two network-position controls covered different sets of
# entry points. These assert the PROPERTY — the servable app carries the middleware — rather
# than that a particular line exists in main(), because the line is what moved.


class _FakeBridge:
    """Minimal stand-in for FastMCP: only streamable_http_app() is used by build_asgi_app."""

    def __init__(self):
        self.built = 0

    def streamable_http_app(self):
        self.built += 1
        from starlette.applications import Starlette
        return Starlette()


def _middleware_classes(app) -> list[str]:
    # Starlette records add_middleware() calls in user_middleware until the stack is built.
    return [m.cls.__name__ for m in getattr(app, "user_middleware", [])]


def _import_bridge():
    """Import http_bridge, SKIPPING rather than ERRORING when its deps are absent.

    Both third-party imports are guarded, not just the one review named. `http_bridge` imports
    `mcp` at module scope, and `_FakeBridge` needs `starlette` — either missing makes a bare
    lazy import fail at COLLECTION as an ERROR, which is the "silently does not run" outcome
    this file exists to avoid. Guarding one and not the other would leave the same hole one
    dependency over.

    Per-test rather than module-level on purpose: only these two tests touch http_bridge, and a
    module-level guard would skip the many tests here that exercise peer_guard alone.
    """
    pytest.importorskip("mcp")
    pytest.importorskip("starlette")
    import http_bridge
    return http_bridge


def test_build_asgi_app_attaches_the_peer_guard():
    http_bridge = _import_bridge()
    app = http_bridge.build_asgi_app(_FakeBridge())
    assert "PeerGuardMiddleware" in _middleware_classes(app)


def test_build_asgi_app_honours_the_documented_opt_out(monkeypatch, caplog):
    monkeypatch.setenv("BRIDGE_ALLOW_ANY_PEER", "1")
    http_bridge = _import_bridge()
    app = http_bridge.build_asgi_app(_FakeBridge())
    assert "PeerGuardMiddleware" not in _middleware_classes(app)
    # Turning the control off must be visible in the journal, not silent.
    assert any("bridge_peer_guard_disabled" in r.getMessage() for r in caplog.records)


def test_main_serves_the_app_build_asgi_app_returns():
    """The guard must be on the path that is actually SERVED, not merely constructible.

    Pinned by source inspection because main() runs a server: what matters is that main hands
    uvicorn the result of build_asgi_app rather than a bare streamable_http_app(), which is the
    exact shape of the defect — a servable app produced by a route the guard does not cover.
    """
    src = (IDX_DIR / "http_bridge.py").read_text(encoding="utf-8")
    main_src = src[src.index("def main("):]
    assert "build_asgi_app(" in main_src
    assert "streamable_http_app()" not in main_src


# ── an HTTP scope's peer must PARSE, whatever shape its absence takes ──
#
# Raised by automated review on revision 13: `("", 0)` gave host == "", which was not None so
# not refused by http_peer_is_admissible, and falsy so admitted as "local" by is_local_peer.
# The table is the point — the fix is not "refuse '' as well", it is that the HTTP path requires
# a positive parse, so no enumeration of absent forms exists to fall behind again.


@pytest.mark.parametrize(
    "host",
    [
        None,          # absent client
        "",            # THE regression: scope["client"] == ("", 0)
        "   ",         # whitespace-only
        "[]",          # brackets that strip to nothing
        "[ ]",
        "unknown",     # a placeholder some layers substitute; not an address
        "localhost",   # a NAME, not a literal — resolution is not a boundary here
    ],
)
def test_http_peer_is_refused_unless_the_host_parses(host):
    assert peer_guard.http_peer_is_admissible(host) is False


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "::1", "[::1]", "169.254.1.1"])
def test_http_peer_still_admits_a_parseable_non_public_address(host):
    """The tightening must not cost the documented loopback health probe."""
    assert peer_guard.http_peer_is_admissible(host) is True


def test_middleware_refuses_an_empty_client_tuple():
    """End to end: the shape review reported, through the middleware rather than the predicate.

    Distinct from the existing `client: ()` case: an EMPTY tuple is falsy, so the middleware
    already derived host=None from it and refused. `("", 0)` is truthy, so it derives host="" —
    which is the value that fell between the two predicates. Asserts downstream was never
    reached, not merely that the status was 403.
    """
    scope = {"type": "http", "path": "/mcp", "client": ("", 0), "headers": []}
    status, _body, downstream = _drive(scope)
    assert status == 403
    assert downstream is False
