#!/usr/bin/env python3
"""
triage_dead_links.py — classify the broken links flagged by health-link-check.

The health-link-check workflow runs lychee and dumps every broken link into a
rolling issue (default #176). lychee gives a flat list — it does not tell you
whether a link is *permanently* dead (domain gone, content deleted) or just
*transiently* unreachable (the CI runner's IP got blocked, rate-limited, or
the server was briefly slow). This tool re-probes each flagged URL from the
maintainer's own vantage point, cross-references the Wayback Machine, and
buckets every URL into a disposition recommendation.

The schema's `status` field is the disposition mechanism:
  - active        -> renders in the READMEs
  - archived-only -> dropped from READMEs, kept in data/index.json (use archive_url)
  - quarantined   -> excluded everywhere
A dead-but-archived entry should become `archived-only`, not be deleted —
the archive_url we already store is the safety net. Genuine deletion is
reserved for "dead AND no archive anywhere".

Default is report-only. `--apply-archived-only` opts in to rewriting the
`status:` field for the unambiguous "dead + has archive_url" cases.

SECURITY — this tool actively connects to hundreds of servers drawn from a
public list; some of those domains have expired and may have been bought by
hostile parties. Every outbound request is hardened:
  - http/https schemes only
  - by default connects directly. With --proxy, all traffic goes through that
    explicit HTTP proxy: the proxy performs DNS resolution and the actual
    connection, so the script never resolves untrusted hostnames itself. This
    is how to run inside a fake-ip / system-resolver-rewriting VPN — point
    --proxy at the VPN tool's local HTTP proxy.
  - client-side pre-filter before a host is connected to (or handed to the
    proxy): IP-literal hosts in private / loopback / link-local / reserved
    ranges (incl. cloud metadata 169.254.169.254) and obviously-internal
    names (localhost, *.local, *.internal, bare single-label hosts, ...) are
    marked unsafe-skip and NEVER sent. For a normal public-looking hostname,
    when running through a proxy the final SSRF defence is the proxy's own
    rule set — ensure your proxy REJECTs RFC1918 / loopback destinations.
  - redirects are handled manually, one hop at a time, with the pre-filter
    re-run on every hop
  - the probe stage NEVER reads the response body — status code and redirect
    target are all we need, so there is no decompression-bomb or
    content-injection surface (the Wayback CDX lookup reads a capped 64 KB,
    from that trusted endpoint only)
  - strict connect/read timeouts; capped redirect hops
  - TLS verification stays ON. The python.org macOS build often ships with no
    usable CA bundle (ssl.get_default_verify_paths() comes back empty), so the
    script locates a real bundle itself — certifi if installed, else a
    well-known system path. --ca-bundle overrides this (use it if auto-detect
    picks the wrong file, or to add a MITM proxy's root CA). With a working
    bundle a genuine cert error is a real signal, not a config artefact.
  - the probe stage uses NO credentials whatsoever
The report only ever contains our own classification plus the original URL
(sanitised, rendered as a plain code span) — never anything fetched back.

Run from repo root. By default connects directly. In a fake-ip or MITM-proxy
environment, pass --proxy http://HOST:PORT (the local HTTP proxy of your VPN
tool); the script self-checks the proxy on startup and aborts if unreachable.

    python3 scripts/ci/triage_dead_links.py [--issue N] [--from-file PATH]
                                            [--proxy URL] [--ca-bundle PEM]
                                            [--apply-archived-only] [--json OUT]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Reuse archive.py's textual YAML accessors (same directory) — do not
# re-implement YAML parsing. archive.py is import-safe (main() is guarded).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from archive import parse_entries, yaml_quote  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
ENTRIES_DIR = ROOT / "data" / "entries"
DEFAULT_ISSUE = "176"
DEFAULT_REPO = "qazbnm456/awesome-web-security"

# --- security constants ---
ALLOWED_SCHEMES = {"http", "https"}
PROBE_TIMEOUT = 15          # seconds, connect + read combined (urllib single knob)
MAX_REDIRECTS = 5
# A real browser UA — lychee's default UA gets anti-bot-blocked a lot, which is
# the single biggest source of false "dead" positives.
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"

# Default: connect directly (empty proxy). In a fake-ip or MITM-proxy
# environment, pass --proxy http://HOST:PORT so the proxy owns DNS + egress.
PROXY_DEFAULT = ""

# Well-known CA bundles, tried in order when neither --ca-bundle nor certifi
# gives us one. The python.org macOS build leaves ssl with no bundle at all,
# so we cannot rely on ssl.create_default_context() finding roots by itself.
_CA_CANDIDATES = (
    "/etc/ssl/cert.pem",                           # macOS / LibreSSL
    "/opt/homebrew/etc/ca-certificates/cert.pem",  # Homebrew (Apple Silicon)
    "/usr/local/etc/openssl@3/cert.pem",           # Homebrew (Intel)
    "/etc/ssl/certs/ca-certificates.crt",          # Debian / Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",            # RHEL / Fedora
)

# Obviously-internal hostnames — refused client-side, never handed to the proxy.
# The bare single-label rule (^[^.]+$) catches names like `intranet`; a real
# public URL always has a dotted domain, so it never hits a real entry.
_INTERNAL_HOST_RE = re.compile(
    r"(\.local|\.internal|\.intranet|\.lan|\.home|\.corp|\.arpa)$|^localhost$|^[^.]+$",
    re.IGNORECASE,
)

# lychee error lines in the rolling issue body look like:
#   * [ERROR] <http://example.com/> | Error (cached)
#   * [404] <http://example.com/x> | Error (cached)
#   * [TIMEOUT] <http://example.com/> | Timeout
LYCHEE_LINE_RE = re.compile(r"^\*\s*\[([A-Z0-9]+)\]\s*<([^>]+)>")

# control chars / ANSI escapes — stripped from any URL before it touches the
# report, so a hostile URL cannot inject terminal escapes or markdown.
_UNSAFE_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

def _ip_is_safe(ip_str: str) -> bool:
    """A resolved IP is safe to connect to only if it is a normal public address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local      # covers 169.254.0.0/16 incl. cloud metadata
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def screen_host(host: str) -> str:
    """Client-side pre-filter before a host is handed to the proxy.

    The script does not resolve DNS itself — the proxy does. This catches the
    cases we *can* judge without DNS:
      "unsafe"   — an IP-literal host in a reserved range, or an obviously
                   internal name; never sent to the proxy
      "delegate" — a normal public-looking hostname; handed to the proxy,
                   which performs resolution + connection and is expected to
                   enforce its own rules against internal destinations
    """
    try:
        ipaddress.ip_address(host)
        return "delegate" if _ip_is_safe(host) else "unsafe"
    except ValueError:
        pass
    if _INTERNAL_HOST_RE.search(host):
        return "unsafe"
    return "delegate"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable urllib's automatic redirect following.

    With this installed, opener.open raises HTTPError on a 3xx instead of
    silently following it — so we can re-run the host pre-filter on each hop
    ourselves before deciding to continue.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def resolve_ca_bundle(explicit: str | None) -> str | None:
    """Find a usable CA bundle path.

    Order: explicit --ca-bundle > certifi (if installed) > a well-known system
    bundle. Returns None only if nothing is found, in which case ssl falls
    back to its built-in defaults (which on the python.org macOS build verify
    nothing — the caller warns about this).
    """
    if explicit:
        return explicit
    try:
        import certifi
        return certifi.where()
    except ImportError:
        pass
    for cand in _CA_CANDIDATES:
        if Path(cand).is_file():
            return cand
    return None


def _build_opener(proxy: str, ca_bundle: str | None,
                  follow_redirects: bool = False) -> urllib.request.OpenerDirector:
    """Build an opener routed through `proxy` (empty string = direct).

    `follow_redirects=False` (the probe opener) raises HTTPError on 3xx so each
    hop can be re-screened; `follow_redirects=True` (the Wayback opener) lets
    urllib follow redirects normally.

    `ca_bundle` is a resolved CA file path (see resolve_ca_bundle). None means
    ssl uses its built-in defaults.
    """
    handlers: list = []
    if not follow_redirects:
        handlers.append(_NoRedirect)
    handlers.append(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}
    ))
    ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle \
        else ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def proxy_sanity_check(opener: urllib.request.OpenerDirector, proxy: str,
                       ca_bundle: str | None) -> tuple[bool, str]:
    """Confirm proxy reachability AND TLS verification before any untrusted URL.

    Probes https://example.com/ so a single check covers both the proxy hop
    and the CA bundle. SSL failures and connection failures get distinct,
    actionable messages.
    """
    label = proxy or "(direct, no proxy)"
    ca = ca_bundle or "ssl-builtin-default"
    try:
        req = urllib.request.Request("https://example.com/", headers={"User-Agent": BROWSER_UA})
        with opener.open(req, timeout=PROBE_TIMEOUT) as resp:
            return True, f"proxy+TLS OK [proxy={label}, ca={ca}] (example.com -> {resp.status})"
    except urllib.error.HTTPError as exc:
        # any HTTP response means proxy + TLS both worked
        return True, f"proxy+TLS OK [proxy={label}, ca={ca}] (example.com -> HTTP {exc.code})"
    except urllib.error.URLError as exc:
        reason = str(getattr(exc, "reason", exc))
        if "CERTIFICATE" in reason.upper() or "SSL" in reason.upper():
            return False, (
                f"TLS verification failed [ca={ca}]: {reason}. The CA bundle "
                "is not verifying real certs — pass a valid one via --ca-bundle "
                "(e.g. --ca-bundle /etc/ssl/cert.pem)."
            )
        return False, (
            f"proxy check failed [proxy={label}]: {reason} — is the proxy "
            "running and reachable at that address? Drop --proxy to connect "
            "directly instead."
        )
    except Exception as exc:
        return False, f"sanity check failed [proxy={label}]: {type(exc).__name__}: {exc}"


def safe_probe(url: str, opener: urllib.request.OpenerDirector) -> dict:
    """Probe a URL through the proxy, pre-filtering hosts and handling
    redirects manually.

    DNS resolution + connection happen in the proxy. This never reads the
    response body. Returns a dict with at least `outcome`:
      ok                 — reached a 2xx
      http-error         — reached a non-3xx error status (`final_status`)
      unsafe             — a hop's host is internal; not sent to the proxy
      bad-scheme         — non-http(s) scheme, or no host
      timeout            — connect/read timed out
      conn-error         — connection-level failure incl. an unresolvable
                           host or a TLS failure (`error`)
      too-many-redirects — exceeded MAX_REDIRECTS
    Also carries `final_url` and `chain` (list of (status, target) hops).
    """
    chain: list[tuple[int, str]] = []
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        parsed = urllib.parse.urlparse(current)
        if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
            return {"outcome": "bad-scheme", "final_url": current, "chain": chain}

        # fail closed: only an explicit "delegate" proceeds — any other
        # screen_host result (now just "unsafe", but defensive for the future)
        # stops the probe.
        if screen_host(parsed.hostname) != "delegate":
            return {"outcome": "unsafe", "final_url": current, "chain": chain}

        req = urllib.request.Request(
            current, method="GET", headers={"User-Agent": BROWSER_UA}
        )
        try:
            with opener.open(req, timeout=PROBE_TIMEOUT) as resp:
                # deliberately do NOT read the body — see module docstring
                return {
                    "outcome": "ok",
                    "final_status": resp.status,
                    "final_url": current,
                    "chain": chain,
                }
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                loc = exc.headers.get("Location")
                if not loc:
                    return {
                        "outcome": "http-error", "final_status": exc.code,
                        "final_url": current, "chain": chain,
                    }
                current = urllib.parse.urljoin(current, loc)
                chain.append((exc.code, current))
                continue  # next hop — host pre-filter re-runs at loop top
            return {
                "outcome": "http-error", "final_status": exc.code,
                "final_url": current, "chain": chain,
            }
        except socket.timeout:
            return {"outcome": "timeout", "final_url": current, "chain": chain}
        except (urllib.error.URLError, ConnectionError, OSError, ValueError) as exc:
            return {
                "outcome": "conn-error", "error": str(exc),
                "final_url": current, "chain": chain,
            }
    return {"outcome": "too-many-redirects", "final_url": current, "chain": chain}


# ---------------------------------------------------------------------------
# Wayback CDX — read-only public API, used as the tiebreaker
# ---------------------------------------------------------------------------

def wayback_last_snapshot(url: str, opener: urllib.request.OpenerDirector):
    """Look up the most recent successful (2xx) Wayback snapshot.

    Returns one of:
      {"timestamp", "original"} — a snapshot exists
      "absent"   — CDX answered, but there is no 2xx snapshot for this URL
      "unknown"  — the CDX query itself failed (503 / timeout / ...) even
                   after retries; archive status could not be determined

    The "absent" vs "unknown" distinction is load-bearing: "absent" can
    justify flagging a removal candidate, "unknown" must NOT — a transient
    CDX outage is not evidence that nothing was archived.

    The request goes through the proxy (consistent egress) and caps the
    timeout + bytes read. `opener` should be a redirect-following opener.
    """
    query = urllib.parse.urlencode({
        "url": url,
        "output": "json",
        "limit": "-5",
        "filter": "statuscode:200",
        "fl": "timestamp,original",
    })
    full = f"{WAYBACK_CDX}?{query}"
    for attempt in range(3):
        try:
            req = urllib.request.Request(full, headers={"User-Agent": BROWSER_UA})
            with opener.open(req, timeout=PROBE_TIMEOUT) as resp:
                raw = resp.read(64 * 1024)
            data = json.loads(raw)
            rows = data[1:] if isinstance(data, list) and len(data) > 1 else []
            if not rows:
                return "absent"
            last = rows[-1]
            return {"timestamp": last[0], "original": last[1]}
        except Exception:
            if attempt < 2:
                time.sleep(2)        # CDX 503s are usually transient
                continue
            return "unknown"
    return "unknown"


# ---------------------------------------------------------------------------
# Entry index
# ---------------------------------------------------------------------------

def load_entry_index() -> dict[str, dict]:
    """Map each entry's primary url -> {id, file, fields}.

    Only the top-level `url` field is indexed (archive.py's parse_entries does
    not descend into the nested `author:` block). A broken link that does not
    match any entry url is most likely a byline/author link or a preamble
    link — surfaced separately in the report, not silently dropped.
    """
    index: dict[str, dict] = {}
    if not ENTRIES_DIR.exists():
        return index
    for yml in sorted(ENTRIES_DIR.glob("*.yml")):
        for entry in parse_entries(yml):
            url = entry["fields"].get("url")
            if isinstance(url, str):
                index[url] = {"id": entry["fields"].get("id"), "file": yml, "fields": entry["fields"]}
    return index


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _dead_reco(entry: dict | None, wayback, reason: str) -> tuple[str, str]:
    """Pick the disposition sub-bucket for a confirmed-dead URL.

    `wayback` is whatever wayback_last_snapshot returned: a dict, "absent",
    or "unknown" (or None if no lookup was done).
    """
    if entry and entry["fields"].get("archive_url"):
        return "dead-archived", f"{reason}; entry already has archive_url -> set status: archived-only"
    if isinstance(wayback, dict):
        return "dead-wayback", (
            f"{reason}; no archive_url but Wayback has a snapshot "
            f"({wayback['timestamp']}) -> archive it, then status: archived-only"
        )
    if wayback == "unknown":
        # CDX outage — must not be mistaken for "no archive exists"
        return "dead-unknown", (
            f"{reason}; Wayback CDX lookup failed (likely a transient outage) "
            "— archive status UNKNOWN; re-run triage when Wayback is up before "
            "deciding removal"
        )
    # "absent" or None: Wayback confirmed (or we have) no snapshot
    return "dead-noarchive", f"{reason}; NO archive anywhere -> removal candidate (review metadata below)"


def _wayback_note(wayback) -> str:
    """A short suffix describing the Wayback lookup result, for ambiguous recos."""
    if isinstance(wayback, dict):
        return f"; Wayback has a snapshot ({wayback['timestamp']})"
    if wayback == "unknown":
        return "; Wayback lookup also failed (could not check)"
    if wayback == "absent":
        return "; Wayback has no snapshot"
    return ""


def classify(probe: dict, wayback, entry: dict | None) -> tuple[str, str]:
    """Return (bucket, recommendation).

    Buckets: dead-archived | dead-wayback | dead-noarchive | dead-unknown
             transient | ambiguous | unsafe-skip
    `wayback` is wayback_last_snapshot's result: a dict, "absent", "unknown",
    or None when no lookup was done.
    """
    outcome = probe["outcome"]

    if outcome == "unsafe":
        return "unsafe-skip", (
            "host is an internal/reserved IP literal or an internal-looking "
            "name — possibly hijacked; NOT visited, review manually"
        )
    if outcome == "bad-scheme":
        return "unsafe-skip", "non-http(s) scheme or missing host — NOT visited, review manually"

    if outcome == "http-error":
        code = probe.get("final_status")
        if code == 410:
            return _dead_reco(entry, wayback, "HTTP 410 Gone")
        if code == 404:
            return _dead_reco(entry, wayback, "HTTP 404 (re-probed with a browser UA)")
        if code in (403, 429):
            return "transient", (
                f"HTTP {code} — anti-bot / rate-limit, not a dead-page signal; leave active"
            )
        if isinstance(code, int) and 500 <= code < 600:
            return "ambiguous", f"HTTP {code} — server error, may be transient; re-check next scan"
        return "ambiguous", f"HTTP {code} — unclassified status; review manually"

    if outcome == "ok":
        if probe.get("chain"):
            final_path = urllib.parse.urlparse(probe["final_url"]).path
            if final_path in ("", "/"):
                return "ambiguous", (
                    "re-probe succeeded but redirects to the site root — the original "
                    "resource is likely gone even though the site is up; review manually"
                )
        return "transient", (
            "re-probe succeeded with a browser UA — lychee's failure was transient "
            "(UA or IP block); leave active"
        )

    if outcome == "timeout":
        return "ambiguous", (
            "timed out on re-probe — slow server or gone; re-check next scan"
            + _wayback_note(wayback)
        )
    if outcome == "conn-error":
        # in proxy mode this also covers an unresolvable host (the proxy could
        # not resolve it) — a possible-dead signal, but not certain enough to
        # confirm, so it stays ambiguous with the Wayback hint attached
        return "ambiguous", (
            f"connection failed ({probe.get('error', '')}) — host may no "
            "longer exist, or a TLS/network issue; review manually"
            + _wayback_note(wayback)
        )
    if outcome == "too-many-redirects":
        return "ambiguous", "redirect loop / too many hops; review manually"

    return "ambiguous", f"unhandled probe outcome: {outcome}"


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

def fetch_broken_urls_from_issue(issue: str, repo: str) -> list[str]:
    """Pull the rolling health issue body via gh and extract the flagged URLs."""
    out = subprocess.run(
        ["gh", "issue", "view", issue, "-R", repo, "--json", "body", "-q", ".body"],
        check=True, capture_output=True, text=True,
    ).stdout
    return _extract_urls(out)


def _extract_urls(body: str) -> list[str]:
    seen: dict[str, None] = {}
    for line in body.splitlines():
        m = LYCHEE_LINE_RE.match(line.strip())
        if m:
            url = m.group(2).strip()
            if url:
                seen.setdefault(url, None)
    return list(seen)


# ---------------------------------------------------------------------------
# Apply (opt-in)
# ---------------------------------------------------------------------------

def write_status(path: Path, entry_id: str, new_status: str) -> bool:
    """Rewrite the `status:` line of one entry in-place. Returns True on success.

    Re-parses the file fresh (line numbers shift as earlier entries are edited),
    matching archive.py's write pattern.
    """
    for entry in parse_entries(path):
        if entry["fields"].get("id") != entry_id:
            continue
        lines = entry["raw"]
        line_no = entry["field_lines"].get("status")
        if line_no is None:
            return False
        lines[line_no] = f"    status: {yaml_quote(new_status)}"
        path.write_text("\n".join(lines), encoding="utf-8")
        return True
    return False


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _safe(url: str) -> str:
    """Strip control chars so a hostile URL cannot inject terminal escapes."""
    return _UNSAFE_CHARS_RE.sub("", url)


def render_report(results: list[dict], applied: int) -> str:
    groups: dict[str, list[dict]] = {}
    for r in results:
        groups.setdefault(r["bucket"], []).append(r)

    order = [
        ("unsafe-skip",    "unsafe — NOT visited (review manually)"),
        ("dead-noarchive", "dead, NO archive anywhere — removal candidates"),
        ("dead-unknown",   "dead, but Wayback was unreachable — re-run triage when Wayback is up"),
        ("dead-wayback",   "dead — archive from Wayback, then status: archived-only"),
        ("dead-archived",  "dead — convert to status: archived-only (entry already has archive_url)"),
        ("ambiguous",      "ambiguous — human review"),
        ("transient",      "transient — leave active, will pass a future scan"),
        ("no-entry-match", "not matched to an entry url (likely a byline/author or preamble link)"),
    ]

    lines: list[str] = []
    lines.append(f"# triage report — {len(results)} urls processed")
    lines.append("")
    counts = " · ".join(f"{k}: {len(groups.get(k, []))}" for k, _ in order)
    lines.append(counts)
    if applied:
        lines.append("")
        lines.append(f"**applied: {applied} entries set to status: archived-only**")
    lines.append("")

    for key, heading in order:
        rows = groups.get(key, [])
        if not rows:
            continue
        lines.append(f"## {heading} ({len(rows)})")
        lines.append("")
        for r in rows:
            entry = r.get("entry")
            tag = f"  [entry: `{entry['id']}` in {entry['file'].name}]" if entry else ""
            lines.append(f"- `{_safe(r['url'])}` — {r['reco']}{tag}")
            # For removal candidates, print the entry metadata inline so the
            # maintainer can judge value without opening the YAML.
            if key == "dead-noarchive" and entry:
                f = entry["fields"]
                lines.append(
                    f"    - title: {f.get('title')!r} · author: {(f.get('author') or '—')} "
                    f"· type: {f.get('type')} · difficulty: {f.get('difficulty')} "
                    f"· date_added: {f.get('date_added')}"
                )
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Triage health-link-check broken links.")
    ap.add_argument("--issue", default=DEFAULT_ISSUE, help="rolling health issue number")
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--from-file", help="read broken-url list from a file instead of gh")
    ap.add_argument("--apply-archived-only", action="store_true",
                    help="rewrite status: archived-only for dead-archived entries")
    ap.add_argument("--proxy", default=PROXY_DEFAULT,
                    help="HTTP proxy for all outbound traffic (default: direct). "
                         "In a fake-ip / MITM-proxy environment point this at "
                         "your VPN tool's local HTTP proxy, e.g. "
                         "http://127.0.0.1:8080")
    ap.add_argument("--ca-bundle", dest="ca_bundle",
                    help="CA bundle path; auto-detected if omitted (certifi or "
                         "a system bundle). Override if auto-detection picks "
                         "the wrong file, or to add a MITM proxy's root CA")
    ap.add_argument("--json", dest="json_out", help="also write the raw results as JSON")
    args = ap.parse_args()

    ca_bundle = resolve_ca_bundle(args.ca_bundle)
    if ca_bundle is None:
        print("warning: no CA bundle found (certifi not installed, no system "
              "bundle at known paths) — HTTPS will likely fail; pass --ca-bundle",
              file=sys.stderr)

    # All outbound traffic goes through the proxy. The probe opener raises on
    # 3xx (manual redirect handling); Wayback gets a redirect-following opener.
    probe_opener = _build_opener(args.proxy, ca_bundle, follow_redirects=False)
    plain_opener = _build_opener(args.proxy, ca_bundle, follow_redirects=True)

    # Confirm proxy reachability + TLS verification before any untrusted URL.
    proxy_ok, proxy_msg = proxy_sanity_check(plain_opener, args.proxy, ca_bundle)
    print(proxy_msg, file=sys.stderr)
    if not proxy_ok:
        return 2

    if args.from_file:
        try:
            body = Path(args.from_file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"cannot read --from-file {args.from_file}: {exc}", file=sys.stderr)
            return 1
        urls = _extract_urls(body)
        src = args.from_file
    else:
        try:
            urls = fetch_broken_urls_from_issue(args.issue, args.repo)
        except subprocess.CalledProcessError as exc:
            print(f"gh issue view failed: {exc.stderr.strip()}", file=sys.stderr)
            return 1
        src = f"#{args.issue}"

    if not urls:
        print(f"no broken-link lines found in {src}", file=sys.stderr)
        return 1

    print(f"processing {len(urls)} urls from {src} ...", file=sys.stderr)
    index = load_entry_index()
    results: list[dict] = []

    for i, url in enumerate(urls, 1):
        print(f"  [{i}/{len(urls)}] {_safe(url)}", file=sys.stderr)
        entry = index.get(url)
        if entry is None:
            results.append({"url": url, "bucket": "no-entry-match",
                            "reco": "no entry has this as its primary url", "entry": None})
            continue
        probe = safe_probe(url, probe_opener)
        # only spend a Wayback lookup when the probe suggests the link is dead
        wayback = None
        if probe["outcome"] in ("http-error", "conn-error", "timeout"):
            wayback = wayback_last_snapshot(url, plain_opener)
        bucket, reco = classify(probe, wayback, entry)
        results.append({"url": url, "bucket": bucket, "reco": reco,
                        "entry": entry, "probe": probe, "wayback": wayback})

    applied = 0
    if args.apply_archived_only:
        for r in results:
            if r["bucket"] == "dead-archived" and r.get("entry"):
                if write_status(r["entry"]["file"], r["entry"]["id"], "archived-only"):
                    applied += 1
        if applied:
            print(f"applied status: archived-only to {applied} entries — "
                  f"run scripts/generate.py and review the diff", file=sys.stderr)

    report = render_report(results, applied)
    print(report)

    if args.json_out:
        serialisable = [
            {k: v for k, v in r.items() if k != "entry"} | (
                {"entry_id": r["entry"]["id"]} if r.get("entry") else {}
            )
            for r in results
        ]
        Path(args.json_out).write_text(json.dumps(serialisable, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
