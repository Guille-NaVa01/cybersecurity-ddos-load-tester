#!/usr/bin/env python3
"""
=============================================================================
DDoS / HTTP & TCP Load Tester for Fail2Ban & Service Stress Testing
=============================================================================
Automated stress-testing tool designed to benchmark and evaluate service
resilience, capacity limits, and Fail2Ban intrusion prevention behavior.

Features:
- CLI arguments via argparse: --host, --port, --path, --concurrency, --duration, --rps, --token, --protocol
- Supports HTTP GET, POST, and TCP/TLS raw handshake stress testing (e.g., LDAP TLS port 636)
- Thread pool concurrency with precision rate limiting
- Real-time periodic status telemetry and comprehensive final benchmark report
=============================================================================
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

REQUEST_TIMEOUT_SECONDS = 3
REPORT_INTERVAL_SECONDS = 2
MAX_DURATION_SECONDS = 600
MAX_CONCURRENCY = 2000
MAX_REQUESTS_PER_SECOND = 5000


class RateLimiter:
    """Limit aggregate request starts across all workers."""

    def __init__(self, requests_per_second: int) -> None:
        self.interval = 1.0 / max(1, requests_per_second)
        self.next_request_at = 0.0
        self.lock = threading.Lock()

    def wait_for_turn(self, stop_event: threading.Event) -> bool:
        with self.lock:
            now = time.monotonic()
            scheduled_at = max(now, self.next_request_at)
            self.next_request_at = scheduled_at + self.interval
        wait_time = max(0.0, scheduled_at - now)
        return not stop_event.wait(wait_time)


def http_request_worker(
    target_url: str,
    headers: dict[str, str],
    deadline: float,
    stop_event: threading.Event,
    rate_limiter: RateLimiter,
    counts: Counter[str],
    latencies: list[float],
    counts_lock: threading.Lock,
) -> None:
    """Sends HTTP requests in a loop until deadline or stop_event."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    
    while not stop_event.is_set() and time.monotonic() < deadline:
        if not rate_limiter.wait_for_turn(stop_event):
            break
        if time.monotonic() >= deadline:
            break

        req = urllib.request.Request(target_url, headers=headers, method="GET")
        start_t = time.monotonic()
        status_code = "000"

        try:
            with opener.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                status_code = str(response.status)
        except urllib.error.HTTPError as err:
            status_code = str(err.code)
        except (urllib.error.URLError, TimeoutError, OSError, ConnectionResetError):
            status_code = "000"  # Connection dropped, timed out, or banned by Fail2Ban / iptables

        duration = time.monotonic() - start_t
        with counts_lock:
            counts[status_code] += 1
            if duration < 10:
                latencies.append(duration)


def tcp_probe_worker(
    host: str,
    port: int,
    use_tls: bool,
    deadline: float,
    stop_event: threading.Event,
    rate_limiter: RateLimiter,
    counts: Counter[str],
    latencies: list[float],
    counts_lock: threading.Lock,
) -> None:
    """Sends raw TCP / TLS connections (e.g. for LDAP port 389 / LDAPS port 636)."""
    while not stop_event.is_set() and time.monotonic() < deadline:
        if not rate_limiter.wait_for_turn(stop_event):
            break
        if time.monotonic() >= deadline:
            break

        start_t = time.monotonic()
        status_code = "000"

        try:
            sock = socket.create_connection((host, port), timeout=REQUEST_TIMEOUT_SECONDS)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(sock, server_hostname=host)
                tls_sock.close()
            else:
                sock.close()
            status_code = "CONN_OK"
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
            status_code = "000"  # Connection blocked or rejected

        duration = time.monotonic() - start_t
        with counts_lock:
            counts[status_code] += 1
            latencies.append(duration)


def snapshot(counts: Counter[str], latencies: list[float], lock: threading.Lock):
    with lock:
        c = counts.copy()
        avg_lat = (sum(latencies) / len(latencies) * 1000) if latencies else 0.0
        return c, avg_lat


def report(target: str, counts: Counter[str], avg_latency: float, elapsed: float, final: bool = False) -> None:
    total = sum(counts.values())
    ok_count = counts.get("200", 0) + counts.get("CONN_OK", 0)
    failed = total - ok_count
    rps = (total / elapsed) if elapsed > 0 else 0

    if final:
        print("\n" + "=" * 70, flush=True)
        print(f" FINAL BENCHMARK REPORT: {target}", flush=True)
        print("=" * 70, flush=True)
        print(f"  • Total Requests Sent : {total:,}", flush=True)
        print(f"  • Success (200 / OK)  : {ok_count:,} ({(ok_count / total * 100 if total else 0):.1f}%)", flush=True)
        print(f"  • Blocked / Fail (000): {failed:,} ({(failed / total * 100 if total else 0):.1f}%)", flush=True)
        print(f"  • Actual Throughput   : {rps:.1f} req/s", flush=True)
        print(f"  • Average Latency     : {avg_latency:.2f} ms", flush=True)
        print(f"  • Response Breakdown  : {dict(counts)}", flush=True)
        
        if counts.get("000", 0) > 0:
            print("\n  [!] Fail2ban / Firewall Alert: '000' responses indicate connections were dropped or banned.", flush=True)
        print("=" * 70 + "\n", flush=True)
    else:
        now_str = datetime.now().strftime("%H:%M:%S")
        print(
            f"  [{now_str}] Elapsed: {elapsed:4.1f}s | Total: {total:5d} | "
            f"OK: {ok_count:5d} | Blocked/Fail: {failed:5d} | "
            f"Rate: {rps:5.1f} rps | Latency: {avg_latency:6.1f} ms",
            flush=True,
        )


def run_test(
    host: str,
    port: int,
    path: str,
    protocol: str,
    concurrency: int,
    duration: int,
    rps: int,
    token: str | None,
    mode: str,
) -> None:
    target_str = f"{protocol}://{host}:{port}{path}" if mode == "http" else f"tcp://{host}:{port} ({'TLS' if protocol == 'https' else 'PLAIN'})"
    print("\n" + "=" * 70, flush=True)
    print(f" STARTING LOAD TEST TARGET: {target_str}", flush=True)
    print(f"  -> Concurrency : {concurrency} worker threads")
    print(f"  -> Target Rate : {rps} req/sec max limit")
    print(f"  -> Duration    : {duration} seconds")
    print(f"  -> Mode        : {mode.upper()}")
    if token:
        print(f"  -> Auth Token  : Bearer {token[:20]}...")
    print("=" * 70, flush=True)

    counts: Counter[str] = Counter()
    latencies: list[float] = []
    lock = threading.Lock()
    stop_event = threading.Event()
    rate_limiter = RateLimiter(rps)
    start_time = time.monotonic()
    deadline = start_time + duration

    headers = {"User-Agent": "Security-Load-Tester/2.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for _ in range(concurrency):
            if mode == "tcp":
                futures.append(
                    executor.submit(
                        tcp_probe_worker,
                        host,
                        port,
                        protocol == "https",
                        deadline,
                        stop_event,
                        rate_limiter,
                        counts,
                        latencies,
                        lock,
                    )
                )
            else:
                target_url = f"{protocol}://{host}:{port}{path}"
                futures.append(
                    executor.submit(
                        http_request_worker,
                        target_url,
                        headers,
                        deadline,
                        stop_event,
                        rate_limiter,
                        counts,
                        latencies,
                        lock,
                    )
                )

        try:
            while time.monotonic() < deadline:
                time.sleep(REPORT_INTERVAL_SECONDS)
                now = time.monotonic()
                c_snap, lat_snap = snapshot(counts, latencies, lock)
                report(target_str, c_snap, lat_snap, elapsed=now - start_time)
        except KeyboardInterrupt:
            print("\n[!] Test interrupted by user (Ctrl+C). Halting workers...", flush=True)
            stop_event.set()
        finally:
            stop_event.set()

        for f in futures:
            f.result()

    total_elapsed = time.monotonic() - start_time
    final_counts, final_lat = snapshot(counts, latencies, lock)
    report(target_str, final_counts, final_lat, elapsed=total_elapsed, final=True)


def sanitize_path(path: str) -> str:
    """Fix Git Bash / MSYS on Windows converting /path into C:/Program Files/Git/path."""
    import re
    if ":" in path and ("Git" in path or "msys" in path or "AppData" in path):
        # Extract the trailing relative path after Git or root
        path = re.sub(r'^[A-Za-z]:.*?[/\\](?:Git|mingw\d+|usr)([/\\]|$)', '/', path, flags=re.IGNORECASE)
        # If it still has drive letter, remove drive prefix
        path = re.sub(r'^[A-Za-z]:', '', path)
    if not path.startswith("/"):
        path = "/" + path
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail2Ban & Service Stress Load Testing Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default=os.getenv("TARGET_HOST", "localhost"), help="Target host or IP address")
    parser.add_argument("--port", type=int, default=int(os.getenv("TARGET_PORT", "8001")), help="Target port number")
    parser.add_argument("--path", default=os.getenv("TARGET_PATH", "/books"), help="HTTP URI path to flood (e.g., /books, /health, /)")
    parser.add_argument("--protocol", choices=["http", "https"], default=os.getenv("PROTOCOL", "http"), help="Protocol to use")
    parser.add_argument("-c", "--concurrency", type=int, default=int(os.getenv("CONCURRENCY", "50")), help="Number of concurrent worker threads")
    parser.add_argument("-d", "--duration", type=int, default=int(os.getenv("DURATION", "20")), help="Duration in seconds for the flood test")
    parser.add_argument("-r", "--rps", type=int, default=int(os.getenv("REQUESTS_PER_SECOND", "100")), help="Maximum request rate per second")
    parser.add_argument("-t", "--token", default=os.getenv("BEARER_TOKEN", None), help="Optional Bearer JWT token for authenticated endpoints")
    parser.add_argument("-m", "--mode", choices=["http", "tcp"], default=os.getenv("TEST_MODE", "http"), help="Testing mode: http or raw tcp/tls")
    
    args = parser.parse_args()
    args.path = sanitize_path(args.path)
    return args


def main() -> None:
    args = parse_args()
    run_test(
        host=args.host,
        port=args.port,
        path=args.path,
        protocol=args.protocol,
        concurrency=args.concurrency,
        duration=args.duration,
        rps=args.rps,
        token=args.token,
        mode=args.mode,
    )


if __name__ == "__main__":
    main()
