"""Bulk route generator for scale and stress testing."""

import ipaddress
import time
from pathlib import Path
from typing import List, Optional

from . import register

PIPE_IN = Path("/run/exabgp/exabgp.in")


def _flowspec_vpn_route(rd: str, dest_prefix: str, redirect_ip: str, rt: str) -> str:
    """Build single FlowSpec-VPN announce string (flat format)."""
    return (
        f"announce flow route rd {rd} destination {dest_prefix} "
        f"redirect {redirect_ip} extended-community [ target:{rt} ]"
    )


def _flowspec_ipv4_route(dest_prefix: str, action: str = "rate-limit 0") -> str:
    """Build single IPv4 FlowSpec SAFI 133 announce string (flat API format)."""
    return f"announce flow route destination {dest_prefix} {action}"


def _flowspec_ipv6_route(dest_prefix: str, action: str = "rate-limit 0") -> str:
    """Build single IPv6 FlowSpec SAFI 133 announce string (flat API format)."""
    return f"announce flow route destination {dest_prefix} {action}"


@register("scale-batch")
def build_batch(
    prefix_range: str,
    rd: str,
    rt: str,
    redirect_ip: str = "10.0.0.230",
    count: int = 1000,
    **kwargs,
) -> List[str]:
    """Generate N FlowSpec-VPN routes from prefix range.

    Args:
        prefix_range: START/MASK-END/MASK (e.g. 10.0.0.0/24-10.0.9.0/24)
        rd: Route distinguisher
        rt: Route target
        redirect_ip: Redirect IP for each route
        count: Max routes to generate (default 1000)

    Returns:
        List of ExaBGP announce strings.
    """
    parts = prefix_range.split("-")
    if len(parts) != 2:
        raise ValueError("prefix_range format: START/MASK-END/MASK (e.g. 10.0.0.0/24-10.0.9.0/24)")

    start_net = ipaddress.ip_network(parts[0].strip(), strict=False)
    end_net = ipaddress.ip_network(parts[1].strip(), strict=False)

    routes = []
    current = int(start_net.network_address)
    end = int(end_net.network_address)
    mask = start_net.prefixlen
    step = 2 ** (32 - mask)

    while current <= end and len(routes) < count:
        prefix = f"{ipaddress.IPv4Address(current)}/{mask}"
        routes.append(_flowspec_vpn_route(rd, prefix, redirect_ip, rt))
        current += step

    return routes


@register("scale-stress")
def build_stress(
    base_prefix: str = "10.0.0.0/24",
    count: int = 20000,
    rd_template: str = "1.1.1.1:{n}",
    rt: str = "1234567:300",
    redirect_ip: str = "10.0.0.230",
    **kwargs,
) -> List[str]:
    """Generate stress-test route set with unique RDs.

    Args:
        base_prefix: Base prefix (third octet incremented per route)
        count: Number of routes
        rd_template: RD template, {n} replaced with 0..count-1
        rt: Route target
        redirect_ip: Redirect IP

    Returns:
        List of ExaBGP announce strings.
    """
    net = ipaddress.ip_network(base_prefix, strict=False)
    base = int(net.network_address)
    mask = net.prefixlen
    step = 2 ** (32 - mask)

    routes = []
    for i in range(count):
        addr = ipaddress.IPv4Address(base + i * step)
        prefix = f"{addr}/{mask}"
        rd = rd_template.format(n=i)
        routes.append(_flowspec_vpn_route(rd, prefix, redirect_ip, rt))

    return routes


@register("scale-flowspec-ipv4")
def build_flowspec_ipv4(
    count: int = 12000,
    base_prefix: str = "10.0.0.0",
    mask: int = 24,
    action: str = "rate-limit 0",
    **kwargs,
) -> List[str]:
    """Generate N unique IPv4 FlowSpec SAFI 133 rules.

    Increments the destination prefix: 10.0.0.0/24, 10.0.1.0/24, ...
    """
    base = int(ipaddress.IPv4Address(base_prefix))
    step = 1 << (32 - mask)
    head = "announce flow route destination "
    tail = f"/{mask} {action}"
    return [f"{head}{_int_to_ipv4(base + i * step)}{tail}" for i in range(count)]


@register("scale-flowspec-ipv6")
def build_flowspec_ipv6(
    count: int = 4000,
    base_prefix: str = "2001:db8::",
    mask: int = 48,
    action: str = "rate-limit 0",
    **kwargs,
) -> List[str]:
    """Generate N unique IPv6 FlowSpec SAFI 133 rules.

    Increments the destination prefix: 2001:db8:0::/48, 2001:db8:1::/48, ...
    """
    base = int(ipaddress.IPv6Address(base_prefix))
    step = 2 ** (128 - mask)
    routes = []
    for i in range(count):
        addr = ipaddress.IPv6Address(base + i * step)
        routes.append(_flowspec_ipv6_route(f"{addr}/{mask}", action))
    return routes


def _flowspec_vpn_route_action(rd: str, dest_prefix: str, rt: str, action: str = "rate-limit 0", source_prefix: str = None) -> str:
    """Build single FlowSpec-VPN SAFI 134 announce string with custom action (flat format)."""
    src = f" source {source_prefix}" if source_prefix else ""
    return f"announce flow route rd {rd} destination {dest_prefix}{src} {action} extended-community [ target:{rt} ]"


def _int_to_ipv4(n: int) -> str:
    """Convert 32-bit int to dotted-quad string without ipaddress overhead."""
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


@register("scale-flowspec-vpn-ipv4")
def build_flowspec_vpn_ipv4(
    count: int = 12000,
    base_prefix: str = "10.0.0.0",
    mask: int = 24,
    rd: str = "1.1.1.1:200",
    rt: str = "300:300",
    action: str = "rate-limit 0",
    base_source: str = None,
    source_mask: int = None,
    **kwargs,
) -> List[str]:
    """Generate N unique IPv4 FlowSpec-VPN SAFI 134 rules.

    Increments destination prefix: 10.0.0.0/24, 10.0.1.0/24, ...
    When base_source is provided, also increments source prefix in parallel.
    Uses VRF ZULU defaults (RD 1.1.1.1:200, RT 300:300).
    """
    base = int(ipaddress.IPv4Address(base_prefix))
    step = 1 << (32 - mask)
    if base_source:
        src_base = int(ipaddress.IPv4Address(base_source))
        smask = source_mask or mask
        src_step = 1 << (32 - smask)
        return [
            _flowspec_vpn_route_action(
                rd, f"{_int_to_ipv4(base + i * step)}/{mask}", rt, action,
                source_prefix=f"{_int_to_ipv4(src_base + i * src_step)}/{smask}")
            for i in range(count)
        ]
    head = f"announce flow route rd {rd} destination "
    tail = f"/{mask} {action} extended-community [ target:{rt} ]"
    return [f"{head}{_int_to_ipv4(base + i * step)}{tail}" for i in range(count)]


@register("scale-flowspec-vpn-ipv6")
def build_flowspec_vpn_ipv6(
    count: int = 4000,
    base_prefix: str = "2001:db8::",
    mask: int = 48,
    rd: str = "1.1.1.1:200",
    rt: str = "1234567:401",
    action: str = "rate-limit 0",
    base_source: str = None,
    source_mask: int = None,
    **kwargs,
) -> List[str]:
    """Generate N unique IPv6 FlowSpec-VPN SAFI 134 rules.

    Increments destination prefix: 2001:db8::/48, 2001:db8:1::/48, ...
    When base_source is provided, also increments source prefix in parallel.
    Uses ipv6-flowspec import RT (default 1234567:401).
    """
    base = int(ipaddress.IPv6Address(base_prefix))
    step = 2 ** (128 - mask)
    src_base = int(ipaddress.IPv6Address(base_source)) if base_source else None
    smask = source_mask or mask
    src_step = 2 ** (128 - smask) if base_source else 0
    routes = []
    for i in range(count):
        addr = ipaddress.IPv6Address(base + i * step)
        src = f"{ipaddress.IPv6Address(src_base + i * src_step)}/{smask}" if base_source else None
        routes.append(_flowspec_vpn_route_action(rd, f"{addr}/{mask}", rt, action, source_prefix=src))
    return routes


def inject_batch(
    routes: List[str],
    rate: Optional[float] = None,
    log_path: Optional[Path] = None,
) -> dict:
    """Inject routes via ExaBGP pipe with optional rate limiting.

    Args:
        routes: List of ExaBGP announce strings
        rate: Routes per second (None = no limit, burst)
        log_path: Optional log path for session.log

    Returns:
        {injected, failed, elapsed_sec, routes_per_sec}
    """
    import session as session_mod

    start = time.perf_counter()
    injected = 0
    failed = 0

    for i, route in enumerate(routes):
        try:
            with open(PIPE_IN, "w") as f:
                f.write(route + "\n")
                f.flush()
            injected += 1
            if log_path and (i + 1) % 100 == 0:
                session_mod.log(f"Injected {i + 1}/{len(routes)}", log_path)
        except Exception as e:
            failed += 1
            if log_path:
                session_mod.log(f"Failed route {i + 1}: {e}", log_path)

        if rate and rate > 0:
            time.sleep(1.0 / rate)

    elapsed = time.perf_counter() - start
    return {
        "injected": injected,
        "failed": failed,
        "total": len(routes),
        "elapsed_sec": round(elapsed, 2),
        "routes_per_sec": round(injected / elapsed, 1) if elapsed > 0 else 0,
    }


def inject_batch_fast(
    routes: List[str],
    batch_size: int = 200,
    inter_batch_delay: float = 0.05,
    log_path: Optional[Path] = None,
) -> dict:
    """Legacy wrapper — calls inject_pipe_turbo for actual work."""
    return inject_pipe_turbo(routes, chunk_size=batch_size, log_path=log_path)


def inject_pipe_turbo(
    routes: List[str],
    chunk_size: int = 2000,
    log_path: Optional[Path] = None,
) -> dict:
    """High-performance injection: single pipe open, bulk os.write, zero delays.

    Opens the FIFO once for the entire injection. Joins chunks into a single
    string and writes via os.write(). The kernel pipe buffer (64KB+) provides
    natural backpressure — os.write() blocks when the buffer is full, which is
    exactly the flow control we need. No artificial delays, no per-batch
    open/close overhead.
    """
    import os as _os
    import session as session_mod

    start = time.perf_counter()
    injected = 0
    failed = 0

    fd = _os.open(str(PIPE_IN), _os.O_WRONLY)
    try:
        for chunk_start in range(0, len(routes), chunk_size):
            chunk = routes[chunk_start:chunk_start + chunk_size]
            payload = "\n".join(chunk) + "\n"
            _os.write(fd, payload.encode())
            injected += len(chunk)

            if log_path and injected % 2000 == 0:
                elapsed_so_far = time.perf_counter() - start
                rps = injected / elapsed_so_far if elapsed_so_far > 0 else 0
                session_mod.log(
                    f"Progress: {injected}/{len(routes)} "
                    f"({elapsed_so_far:.1f}s, {rps:.0f} rps)",
                    log_path,
                )
    except Exception as e:
        failed = len(routes) - injected
        if log_path:
            session_mod.log(f"Pipe write failed at {injected}: {e}", log_path)
    finally:
        _os.close(fd)

    elapsed = time.perf_counter() - start
    return {
        "injected": injected,
        "failed": failed,
        "total": len(routes),
        "elapsed_sec": round(elapsed, 2),
        "routes_per_sec": round(injected / elapsed, 1) if elapsed > 0 else 0,
    }


def _announce_to_withdraw(announce_str: str) -> str:
    """Convert announce string to withdraw, stripping non-NLRI action attributes."""
    import re
    w = announce_str.replace("announce", "withdraw", 1) if announce_str.startswith("announce") else f"withdraw {announce_str}"
    w = re.sub(r'\s+rate-limit\s+\S+', '', w)
    w = re.sub(r'\s+redirect\s+\S+', '', w)
    w = re.sub(r'\s+extended-community\s+\[.*?\]', '', w)
    return w.strip()


def withdraw_all(routes: List[str], batch_size: int = 200, inter_batch_delay: float = 0.05) -> dict:
    """Withdraw all routes by converting announce→withdraw and sending via pipe."""
    withdraw_routes = [_announce_to_withdraw(r) for r in routes]
    return inject_batch_fast(withdraw_routes, batch_size, inter_batch_delay)


def reconstruct_injected_routes(mode: str, params: dict, count: int) -> List[str]:
    """Reconstruct routes from stored injection params, handling builder changes.

    Uses stored params to regenerate the EXACT format originally injected.
    Handles legacy SAFI 133 injections (no rd in params) for flowspec-vpn-ipv6.
    """
    from . import BUILDERS
    params_copy = dict(params)
    params_copy["count"] = count

    if mode == "flowspec-vpn-ipv6" and not params.get("rd"):
        base_prefix = params.get("base_prefix", "2001:db8::")
        mask = params.get("mask", 48)
        action = params.get("action", "rate-limit 0")
        base = int(ipaddress.IPv6Address(base_prefix))
        step = 2 ** (128 - mask)
        return [
            _flowspec_ipv6_route(f"{ipaddress.IPv6Address(base + i * step)}/{mask}", action)
            for i in range(count)
        ]

    builder = BUILDERS.get(f"scale-{mode}")
    if builder:
        return builder(**params_copy)
    return []
