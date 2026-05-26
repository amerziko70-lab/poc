CVE-2026-23918 Apache mod_http2 Double-Free Detector


 h2ghost.mp4 
python3 h2ghost.py -h
                                                    
usage: h2ghost.py [-h] [--host HOST] [--port PORT] [--tls] [--no-tls] [--iterations ITERATIONS]
                  [--burst-n BURST_N] [--timeout TIMEOUT] [--crash-threshold CRASH_THRESHOLD]
                  [--crash-multiplier CRASH_MULTIPLIER] [--crash-min-delta CRASH_MIN_DELTA]
                  [--output OUTPUT] [--check-only] [--skip-check] [--verbose]
                  [TARGET]

Apache mod_http2 CVE-2026-23918 - double-free detector

positional arguments:
  TARGET                https://host:port http://host host:port host IP

options:
  -h, --help            show this help message and exit
  --host HOST           Target host (alt to positional)
  --port PORT           Target port (inferred from scheme/target if omitted)
  --tls                 Force TLS/HTTPS (default: auto-detect)
  --no-tls              Force plain TCP / h2c
  --iterations ITERATIONS
  --burst-n BURST_N     Triggers in check phase (default 10)
  --timeout TIMEOUT     Connection timeout s (default 2.5; use 5+ for internet)
  --crash-threshold CRASH_THRESHOLD
                        Fallback absolute ms when no baseline (default 150)
  --crash-multiplier CRASH_MULTIPLIER
                        reconnect/baseline ratio to flag as crash (default 1.3x)
  --crash-min-delta CRASH_MIN_DELTA
                        min ms above baseline (AND ratio) to flag crash (default 80ms)
  --output OUTPUT
  --check-only
  --skip-check
  --verbose

Crash detection logic
---------------------
  Trigger connection closing is NORMAL on both servers.
  A crash requires: PING fails on a FRESH connection AND
  reconnect > 150 ms (MPM restart delay).

Examples
--------
  python3 h2ghost.py https://127.0.0.1:9443 --check-only
  python3 h2ghost.py 127.0.0.1:7443 --check-only
  python3 h2ghost.py 127.0.0.1:9443 --iterations 200
  python3 h2ghost.py https://example.com --burst-n 20
Vulnerability Summary
Field	Value
CVE	CVE-2026-23918
Severity	High
CVSS	8.8
Component	Apache httpd mod_http2
Impact	Denial of Service / Potential RCE
Fixed Version	Apache httpd 2.4.67 / mod_http2 2.0.37
Technical Details
DoS: trivial trigger using:

1 connection
2 HTTP/2 frames
Potential RCE vector

APR mmap allocator
Debian / Docker environments
Fix

Apache httpd 2.4.67
mod_http2 2.0.37
Credits
Vulnerability Discovery
Bartlomiej Dmitruk - Striga.ai
Stanislaw Strzalkowski - ISEC.pl
Detector Script
Alex Hernandez aka (@_alt3kx_)
References
https://www.cve.org/CVERecord?id=CVE-2026-23918
https://httpd.apache.org/security/vulnerabilities_24.html
https://github.com/apache/httpd/blob/trunk/CHANGES
https://bz.apache.org/bugzilla/show_bug.cgi?id=69899
Disclaimer
This project is provided strictly for:

Authorized security assessments
Defensive testing
Educational research
Unauthorized testing against systems without explicit written permission may violate applicable laws.

The author assumes no liability for misuse.
