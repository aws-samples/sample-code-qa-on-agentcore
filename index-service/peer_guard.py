"""In-process peer-address admission check for the index bridge (AppSec finding 608d4a22).

WHY THIS EXISTS, and what it is NOT.

The bridge has no application authentication: anything that can reach the port can read any
indexed source (`read_file` / `glob_files` / `search_files`) and enumerate the graph. The deployed
unit binds `0.0.0.0` on purpose — uvicorn binds one address, the AgentCore runtime connects over
the VPC by private IP, and the loopback `/health` probe must keep working — so the security group
is, as shipped, the ONLY control. That is a single point of failure: one unexpected SG rule, route,
or peering and the source-read API is exposed with nothing else in the way.

This module is the stopgap the AppSec review asked for. It is NOT authentication, and it must not
be described as such: it authorizes by network position, exactly like the SG does, so it adds a
SECOND independent enforcement point rather than a new kind of control. Its value is that it lives
in the process and cannot be widened by an infrastructure edit.

WHAT IS ALLOWED
  * loopback peers — the health probe (`curl 127.0.0.1/health`) and anything else on the host;
  * RFC1918 / RFC4193 private and link-local peers — the AgentCore runtime and, when a load
    balancer is in front, the LB's own in-VPC address.
Everything else is refused with 403 and logged once per rejected peer.

WHAT IS DELIBERATELY IGNORED
  `X-Forwarded-For` and friends. A forwarding header is set by whoever is talking to us, so
  trusting it would let the caller name its own address and defeat the whole check. Only the real
  socket peer counts. Consequence to know: if a deployment ever fronts this bridge with a proxy
  OUTSIDE the VPC, the peer becomes that proxy's public address and this check will refuse it —
  set BRIDGE_ALLOW_ANY_PEER=1 for that topology and rely on the SG alone, deliberately.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os

logger = logging.getLogger("http_bridge.peer_guard")

# Peers already reported, so a scanner cannot turn the log into an amplification channel.
_reported: set[str] = set()

# Bounded on purpose. `_reported` exists to keep one rejected peer from filling the log, but an
# unbounded set turns that dedup into a memory leak under exactly the condition this guard is meant
# to survive: a wider-than-intended security group or route table exposes the port, an internet-wide
# scan arrives, and every distinct source address is retained for the process lifetime. The bridge is
# a long-lived resident process, so the growth has no natural end. The cap is far above any plausible
# in-VPC caller population, so reaching it is itself the signal that something is scanning.
MAX_REPORTED_PEERS = 1024
_report_cap_hit = False


def allow_any_peer() -> bool:
    """True when the operator has deliberately disabled the check.

    Read at call time rather than import time so a test (and an operator editing the unit's
    environment) does not depend on module import order.
    """
    return os.environ.get("BRIDGE_ALLOW_ANY_PEER", "").strip().lower() in ("1", "true", "yes")


def is_local_peer(host: str | None) -> bool:
    """True when `host` is a loopback, private, or link-local address.

    Classification is by ADDRESS via `ipaddress`, never by string shape: a prefix test such as
    `host.startswith("10.")` would also accept `10.evil.com`, and the same defect in the agent
    container's loopback check accepted `127.0.0.1.evil.com`. A peer address arrives from the
    socket layer as a literal, so a value that does not parse is not a peer we can vouch for and
    is refused.

    SCOPE NOTE: `is_private` is broader than RFC1918 — it covers every special-purpose,
    non-globally-routable block, including the documentation ranges (192.0.2/24, 198.51.100/24,
    203.0.113/24, 2001:db8::/32) and the benchmarking range. Those are therefore admitted. That is
    acceptable here because the property being enforced is "the peer is not on the public
    internet", and none of those blocks is routable across it; it does mean this predicate must
    not be reused anywhere that needs a strict RFC1918 test.
    """
    if not host:
        # A missing peer means a transport with no address (in-process/ASGI test client, or a
        # unix socket). Those cannot come from the network, so treat them as local. This
        # short-circuit is what makes this predicate WRONG for a real HTTP scope — see
        # http_peer_is_admissible, which is built on the parse below WITHOUT this branch.
        return True
    return _parses_as_non_public_address(host)


def _parses_as_non_public_address(host: str | None) -> bool:
    """True only when `host` PARSES as a loopback, private, or link-local address.

    The admission core, factored out so the two callers do not each maintain their own idea of
    what counts as "no peer here". That enumeration is exactly what drifted: is_local_peer
    short-circuits on `not host` (EVERY falsy value) while http_peer_is_admissible enumerated
    only `None`, so an ASGI scope delivering `client == ("", 0)` produced `host == ""` — not
    None, so not refused there; falsy, so admitted as "local" here. Automated review found it
    on revision 13.

    The repair is not a longer list of falsy forms to refuse. It is that a caller needing
    fail-closed behaviour asks for a POSITIVE result: absent, empty, blank, bracketed-empty and
    unparseable all fail to produce an address and are refused, with no list to keep in sync.

    `host is None` is guarded because `.strip()` would raise on it, not as a policy case — and
    it returns False, the safe direction, for the same reason.
    """
    if host is None:
        return False
    h = host.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def peer_is_admissible(host: str | None) -> bool:
    """The whole admission decision, as one testable predicate.

    Treats a missing host as local, which is correct for a transport that HAS no address
    (in-process ASGI, a unix socket). For a real HTTP scope use `http_peer_is_admissible`
    instead — it refuses every peer it cannot identify, not just a `None` one; see the note
    there for why that distinction is the whole point and why phrasing it as a single case is
    what let the empty string through.
    """
    return allow_any_peer() or is_local_peer(host)


def http_peer_is_admissible(host: str | None) -> bool:
    """Admission decision for a real `http` ASGI scope.

    Differs from `peer_is_admissible` on the whole ABSENT class, not on one value: a peer this
    process cannot identify is REFUSED here. That earlier docstring said "ONE case, deliberately"
    and named `None`, and the code matched the docstring — which is precisely how the empty
    string got through. The difference is a property, not a list.

    `is_local_peer(None) is True` is right for the predicate — a transport with no address cannot
    have come from the network. Applying that to a real HTTP scope inverted the control: any server
    or fronting layer delivering an HTTP scope without a usable `client` would admit an external
    caller straight to the source-read handlers. For a check whose entire purpose is authorization
    by network position, an unidentifiable peer is the one case that must not be waved through —
    the same fail-open shape as the account-lookup path in provision_network.sh, reached by a
    missing value rather than a failed call.

    Costs nothing operationally: the documented loopback probe arrives over TCP as 127.0.0.1, which
    parses. An operator who genuinely fronts this bridge from outside the VPC still has
    BRIDGE_ALLOW_ANY_PEER=1.

    This lives as a named predicate rather than inline in the middleware so the decision stays
    testable in one place; inlining it is how the two sides of a check drift apart.
    """
    if allow_any_peer():
        return True
    # Requires a POSITIVE result rather than refusing an enumerated set of "absent" forms.
    # The enumerated version of this line was `if host is None: return False` followed by a
    # delegation to is_local_peer — and is_local_peer's own short-circuit is `not host`, so the
    # two disagreed about the empty string and an `("", 0)` client was ADMITTED. There is now no
    # list of absent forms here to fall out of sync with: a host that does not parse as a
    # non-public address never produces True, whatever shape its absence takes.
    return _parses_as_non_public_address(host)


def log_rejection(host: str | None, path: str) -> None:
    """Record a refused peer once, with enough detail to be actionable in an incident."""
    global _report_cap_hit
    key = host or "<none>"
    if key in _reported:
        return
    if len(_reported) >= MAX_REPORTED_PEERS:
        # Stop tracking new peers rather than evicting: the set is what makes the logging
        # idempotent, so recycling entries would let a scan re-log the same addresses forever and
        # trade the memory leak for a log flood. One line records that the cap was reached, which
        # is the actionable fact — the individual scanner addresses past this point are noise.
        if not _report_cap_hit:
            _report_cap_hit = True
            logger.warning(json.dumps({
                "event": "bridge_peer_rejected_log_capped",
                "distinct_peers": len(_reported),
                "detail": f"more than {MAX_REPORTED_PEERS} distinct peers have been refused; "
                          "further rejections are still enforced but no longer logged per-peer. "
                          "This many distinct sources means the port is reachable from a wider "
                          "network than intended — check the security group and route table.",
            }))
        return
    _reported.add(key)
    logger.warning(json.dumps({
        "event": "bridge_peer_rejected",
        "peer": key,
        "path": path,
        "detail": "peer is neither loopback nor a private address; the bridge serves indexed "
                  "source and is intended for in-VPC access only. A peer reaching this line "
                  "means the security group or route table is wider than intended. Set "
                  "BRIDGE_ALLOW_ANY_PEER=1 only if a non-VPC proxy fronts this bridge by design.",
    }))


class PeerGuardMiddleware:
    """Raw ASGI middleware refusing non-local peers before any handler runs.

    Written against the ASGI interface rather than Starlette's BaseHTTPMiddleware on purpose:
    BaseHTTPMiddleware buffers the response, which would break the streamable-HTTP transport this
    bridge exists to serve. Non-HTTP scopes (lifespan, websocket) pass straight through.
    """

    def __init__(self, app: object) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: object, send: object) -> None:  # type: ignore[override]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)  # type: ignore[operator]
            return
        client = scope.get("client") or ()
        host = client[0] if client else None
        # An HTTP scope with no identifiable peer is REFUSED — see http_peer_is_admissible for why
        # that differs from the bare predicate, and why the difference is the whole point.
        if http_peer_is_admissible(host):
            await self.app(scope, receive, send)  # type: ignore[operator]
            return
        log_rejection(host, str(scope.get("path", "")))
        body = b'{"error":"forbidden","detail":"peer not permitted"}'
        await send({  # type: ignore[operator]
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})  # type: ignore[operator]
