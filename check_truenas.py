#!/usr/bin/env python3
"""
check_truenas.py - Icinga2/Nagios plugin for TrueNAS CORE/SCALE via SNMP
Supports SNMPv2c and SNMPv3
Author: Custom plugin for Icinga2/IcingaDirector
Version: 1.1

Modes:
  --type info   : Always returns OK (or UNKNOWN if SNMP fails entirely).
                  Collects perfdata for CPU, RAM, Disk Space,
                  Interface Traffic, Disk Temperatures.
  --type health : Returns OK/WARNING/CRITICAL based on ZFS pool state.
                  Alerts on DEGRADED, FAULTED, UNAVAIL, REMOVED pools.

Changelog v1.1:
  - Interface byte counters now emit the Nagios 'c' (counter) UOM instead of
    'B' (gauge), enabling proper rate graphing in downstream backends.
  - Memory used_mb / free_mb are now derived from the SNMP used_pct so all
    memory numbers are internally consistent (previously used_pct and
    used_mb/total_mb disagreed because the FREENAS-MIB defines them
    with different accounting rules).
  - check_info now surfaces UNKNOWN if SNMP returns no data at all, instead
    of a misleading "OK - No data collected".
  - check_info status line leads with ZFS pool state (most operationally
    critical) instead of CPU load.
  - check_info respects --include-boot to match check_health behavior
    (boot pool excluded from info output by default).

FREENAS-MIB OIDs used:
  1.3.6.1.4.1.50536.1.1  - zpoolTable (pool name, size, used, health)
  1.3.6.1.4.1.50536.1.4  - memory/cpu stats
  1.3.6.1.4.1.50536.3.1  - disk temperature table
  1.3.6.1.2.1.2.2.1      - ifTable (standard MIB-II for interfaces)
  1.3.6.1.2.1.31.1.1.1   - ifXTable (64-bit counters for interfaces)
"""

import argparse
import sys
import subprocess
import re

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
EXIT_OK       = 0
EXIT_WARNING  = 1
EXIT_CRITICAL = 2
EXIT_UNKNOWN  = 3

# ---------------------------------------------------------------------------
# ZFS pool health states
# value 0 = ONLINE (OK)
# Non-zero values indicate a problem state
# Reference: FREENAS-MIB zpoolHealth
# ---------------------------------------------------------------------------
POOL_HEALTH_STATES = {
    0: "ONLINE",
    1: "DEGRADED",
    2: "FAULTED",
    3: "OFFLINE",
    4: "UNAVAIL",
    5: "REMOVED",
    6: "ERROR",
}

POOL_HEALTH_OK       = {0}
POOL_HEALTH_WARNING  = {1, 3}   # DEGRADED, OFFLINE
POOL_HEALTH_CRITICAL = {2, 4, 5, 6}  # FAULTED, UNAVAIL, REMOVED, ERROR

# ---------------------------------------------------------------------------
# SNMP helpers
# ---------------------------------------------------------------------------

def build_snmp_args(args):
    """Build common snmp CLI arguments based on version."""
    if args.snmp_version == "2c":
        return ["-v2c", "-c", args.community]
    elif args.snmp_version == "3":
        snmpv3 = ["-v3", "-u", args.v3_user]
        if args.v3_level:
            snmpv3 += ["-l", args.v3_level]
        if args.v3_auth_proto:
            snmpv3 += ["-a", args.v3_auth_proto]
        if args.v3_auth:
            snmpv3 += ["-A", args.v3_auth]
        if args.v3_priv_proto:
            snmpv3 += ["-x", args.v3_priv_proto]
        if args.v3_priv:
            snmpv3 += ["-X", args.v3_priv]
        return snmpv3
    else:
        print(f"UNKNOWN - Unsupported SNMP version: {args.snmp_version}")
        sys.exit(EXIT_UNKNOWN)


def snmpget(args, oid):
    """Run snmpget and return raw output string."""
    cmd = ["snmpget", "-Ovq", "-t", str(args.timeout), "-r", "2"] \
          + build_snmp_args(args) + [args.host, oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout + 5)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        print("UNKNOWN - snmpget not found. Install net-snmp-utils.")
        sys.exit(EXIT_UNKNOWN)


def snmpwalk(args, oid):
    """Run snmpwalk and return list of (oid_suffix, value) tuples."""
    cmd = ["snmpwalk", "-Oqn", "-t", str(args.timeout), "-r", "2"] \
          + build_snmp_args(args) + [args.host, oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout + 10)
        lines = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                lines.append((parts[0], parts[1].strip().strip('"')))
        return lines
    except subprocess.TimeoutExpired:
        return []
    except FileNotFoundError:
        print("UNKNOWN - snmpwalk not found. Install net-snmp-utils.")
        sys.exit(EXIT_UNKNOWN)


def snmpwalk_values(args, oid):
    """Return just values from snmpwalk as a list."""
    return [v for _, v in snmpwalk(args, oid)]


def snmpwalk_indexed(args, oid):
    """Return dict of {last_index: value} from snmpwalk."""
    result = {}
    for full_oid, value in snmpwalk(args, oid):
        idx = full_oid.rsplit(".", 1)[-1]
        result[idx] = value
    return result


def safe_int(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def safe_float(val, default=0.0):
    try:
        return float(val)
    except (ValueError, TypeError):
        return default

# ---------------------------------------------------------------------------
# Data collection functions
# ---------------------------------------------------------------------------

def get_pool_data(args):
    """
    Collect ZFS pool data from FREENAS-MIB zpoolTable.
    Returns list of dicts with pool info.

    OIDs:
      .50536.1.1.1.1.2.N = pool name
      .50536.1.1.1.1.3.N = alloc units (block size in bytes)
      .50536.1.1.1.1.4.N = size (in alloc units)
      .50536.1.1.1.1.5.N = used (in alloc units)
      .50536.1.1.1.1.6.N = available (in alloc units)
      .50536.1.1.1.1.7.N = health (0=ONLINE, 1=DEGRADED, etc.)
    """
    base = ".1.3.6.1.4.1.50536.1.1.1.1"
    names   = snmpwalk_indexed(args, base + ".2")
    units   = snmpwalk_indexed(args, base + ".3")
    sizes   = snmpwalk_indexed(args, base + ".4")
    used    = snmpwalk_indexed(args, base + ".5")
    avail   = snmpwalk_indexed(args, base + ".6")
    health  = snmpwalk_indexed(args, base + ".7")

    pools = []
    for idx, name in names.items():
        unit      = safe_int(units.get(idx, 4096))
        size_b    = safe_int(sizes.get(idx, 0)) * unit
        used_b    = safe_int(used.get(idx, 0)) * unit
        avail_b   = safe_int(avail.get(idx, 0)) * unit
        health_v  = safe_int(health.get(idx, 0))
        used_pct  = round((used_b / size_b * 100), 2) if size_b > 0 else 0.0

        pools.append({
            "name":      name,
            "size_gb":   round(size_b / 1073741824, 2),
            "used_gb":   round(used_b / 1073741824, 2),
            "avail_gb":  round(avail_b / 1073741824, 2),
            "used_pct":  used_pct,
            "health":    health_v,
            "health_str": POOL_HEALTH_STATES.get(health_v, f"UNKNOWN({health_v})")
        })
    return pools


def get_memory_data(args):
    """
    Collect memory stats from FREENAS-MIB.

    The FREENAS-MIB defines "free" and "used_pct" with different accounting
    rules (one counts ARC/cache as free, the other doesn't). To keep the
    emitted perfdata internally consistent, we treat the MIB-reported
    used_pct as the source of truth and derive used_mb / free_mb from it.

    OIDs:
      .50536.1.4.1.0  = mem_total (pages)
      .50536.1.4.9.0  = mem_free_pct (string, e.g. "97.79")
      .50536.1.4.10.0 = mem_used_pct (string, e.g. "2.21")
    """
    base = ".1.3.6.1.4.1.50536.1.4"
    total_pages = safe_int(snmpget(args, base + ".1.0"))

    free_pct_raw = snmpget(args, base + ".9.0") or "0"
    used_pct_raw = snmpget(args, base + ".10.0") or "0"

    free_pct = safe_float(free_pct_raw.strip('"'))
    used_pct = safe_float(used_pct_raw.strip('"'))

    # Page size on FreeBSD is typically 4096 bytes
    page_size = 4096
    total_mb  = round((total_pages * page_size) / 1048576, 2)

    # Derive absolute MB values from the percentage so all memory metrics
    # agree with each other (fixes previous bug where used_pct and
    # used_mb/total_mb implied different percentages).
    used_mb = round(total_mb * (used_pct / 100), 2) if total_mb > 0 else 0.0
    free_mb = round(total_mb - used_mb, 2)

    return {
        "total_mb":  total_mb,
        "used_mb":   used_mb,
        "free_mb":   free_mb,
        "used_pct":  used_pct,
        "free_pct":  free_pct,
    }


def get_cpu_data(args):
    """
    Collect CPU load from UCD-SNMP-MIB (standard, works on FreeBSD).
    OIDs:
      .1.3.6.1.4.1.2021.10.1.3.1 = load 1min
      .1.3.6.1.4.1.2021.10.1.3.2 = load 5min
      .1.3.6.1.4.1.2021.10.1.3.3 = load 15min
    """
    base = ".1.3.6.1.4.1.2021.10.1.3"
    load1  = safe_float(snmpget(args, base + ".1"))
    load5  = safe_float(snmpget(args, base + ".2"))
    load15 = safe_float(snmpget(args, base + ".3"))
    return {
        "load1":  load1,
        "load5":  load5,
        "load15": load15,
    }


def get_interface_data(args):
    """
    Collect interface traffic using standard MIB-II ifXTable (64-bit counters).
    OIDs:
      .1.3.6.1.2.1.2.2.1.2.N    = ifDescr (interface name)
      .1.3.6.1.2.1.31.1.1.1.6.N = ifHCInOctets  (bytes in,  64-bit)
      .1.3.6.1.2.1.31.1.1.1.10.N= ifHCOutOctets (bytes out, 64-bit)
      .1.3.6.1.2.1.2.2.1.8.N    = ifOperStatus (1=up, 2=down)
    """
    names      = snmpwalk_indexed(args, ".1.3.6.1.2.1.2.2.1.2")
    in_octets  = snmpwalk_indexed(args, ".1.3.6.1.2.1.31.1.1.1.6")
    out_octets = snmpwalk_indexed(args, ".1.3.6.1.2.1.31.1.1.1.10")
    oper_status= snmpwalk_indexed(args, ".1.3.6.1.2.1.2.2.1.8")

    interfaces = []
    skip_patterns = ["pflog", "enc", "gif", "stf", "faith"]
    for idx, name in names.items():
        if any(p in name.lower() for p in skip_patterns):
            continue
        in_b  = safe_int(in_octets.get(idx, 0))
        out_b = safe_int(out_octets.get(idx, 0))
        status = safe_int(oper_status.get(idx, 2))
        interfaces.append({
            "name":    name,
            "in_b":    in_b,
            "out_b":   out_b,
            "status":  "up" if status == 1 else "down",
        })
    return interfaces


def get_disk_temps(args):
    """
    Collect disk temperatures from FREENAS-MIB.
    OIDs:
      .1.3.6.1.4.1.50536.3.1.2.N = disk name (da0, ada0, etc.)
      .1.3.6.1.4.1.50536.3.1.3.N = temperature in millidegrees C
    """
    names = snmpwalk_indexed(args, ".1.3.6.1.4.1.50536.3.1.2")
    temps = snmpwalk_indexed(args, ".1.3.6.1.4.1.50536.3.1.3")
    disks = []
    for idx, name in names.items():
        temp_mc = safe_int(temps.get(idx, 0))
        temp_c  = round(temp_mc / 1000, 1)
        disks.append({
            "name":   name,
            "temp_c": temp_c,
        })
    return sorted(disks, key=lambda d: d["name"])

# ---------------------------------------------------------------------------
# Check modes
# ---------------------------------------------------------------------------

def check_health(args):
    """
    Check ZFS pool health. Returns CRITICAL/WARNING/OK.
    Only monitors pools matching --pool filter (default: all except boot).
    """
    pools = get_pool_data(args)
    if not pools:
        print("UNKNOWN - No ZFS pool data received via SNMP. Check SNMP connectivity.")
        sys.exit(EXIT_UNKNOWN)

    # Filter pools if --pool specified
    if args.pool:
        pools = [p for p in pools if p["name"] == args.pool]
        if not pools:
            print(f"UNKNOWN - Pool '{args.pool}' not found. Available pools: "
                  + ", ".join(p["name"] for p in get_pool_data(args)))
            sys.exit(EXIT_UNKNOWN)

    # Skip boot pool by default unless explicitly requested
    if not args.pool and not args.include_boot:
        pools = [p for p in pools if "boot" not in p["name"].lower()]

    critical_pools = []
    warning_pools  = []
    ok_pools       = []

    for p in pools:
        h = p["health"]
        if h in POOL_HEALTH_CRITICAL:
            critical_pools.append(p)
        elif h in POOL_HEALTH_WARNING:
            warning_pools.append(p)
        else:
            ok_pools.append(p)

    # Build perfdata
    perfdata_parts = []
    for p in pools:
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', p["name"])
        perfdata_parts.append(
            f"'{safe_name}_used_pct'={p['used_pct']}%;;;0;100"
        )
        perfdata_parts.append(
            f"'{safe_name}_used_gb'={p['used_gb']}GB;;;0;{p['size_gb']}"
        )
        perfdata_parts.append(
            f"'{safe_name}_health'={p['health']};1;2;0;6"
        )
    perfdata = " ".join(perfdata_parts)

    # Build status messages
    def pool_summary(p):
        return (f"{p['name']} [{p['health_str']}] "
                f"{p['used_gb']}GB/{p['size_gb']}GB ({p['used_pct']}% used)")

    if critical_pools:
        msgs = [pool_summary(p) for p in critical_pools]
        detail = " | ".join(msgs)
        print(f"CRITICAL - ZFS Pool FAILURE: {detail} | {perfdata}")
        sys.exit(EXIT_CRITICAL)

    if warning_pools:
        msgs = [pool_summary(p) for p in warning_pools]
        detail = " | ".join(msgs)
        print(f"WARNING - ZFS Pool DEGRADED: {detail} | {perfdata}")
        sys.exit(EXIT_WARNING)

    ok_msgs = [pool_summary(p) for p in ok_pools]
    detail = " | ".join(ok_msgs)
    print(f"OK - All ZFS pools healthy: {detail} | {perfdata}")
    sys.exit(EXIT_OK)


def check_info(args):
    """
    Collect all metrics and return OK with full perfdata.
    Never alerts on thresholds. Intended for dashboards/graphs only.
    Returns UNKNOWN if SNMP collection yields no data at all.

    Status line ordering (most to least operationally critical):
      1. ZFS Pools
      2. Memory
      3. CPU Load
      4. Interface Traffic
      5. Disk Temperatures
    """
    perfdata_parts = []
    status_lines   = []

    # --- ZFS Pools (lead with this - most critical for TrueNAS) ---
    pools = get_pool_data(args)
    # Respect --include-boot for consistency with check_health
    if not args.include_boot:
        pools = [p for p in pools if "boot" not in p["name"].lower()]

    for p in pools:
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', p["name"])
        perfdata_parts += [
            f"'{safe_name}_used_pct'={p['used_pct']}%;;;0;100",
            f"'{safe_name}_used_gb'={p['used_gb']}GB;;;0;{p['size_gb']}",
            f"'{safe_name}_avail_gb'={p['avail_gb']}GB;;;0;{p['size_gb']}",
        ]
    if pools:
        pool_summary = ", ".join(
            f"{p['name']}: {p['used_pct']}% ({p['avail_gb']}GB free)"
            for p in pools
        )
        status_lines.append(f"Pools: {pool_summary}")

    # --- Memory ---
    mem = get_memory_data(args)
    if mem["total_mb"] > 0:
        perfdata_parts += [
            f"'mem_used_pct'={mem['used_pct']}%;;;0;100",
            f"'mem_used_mb'={mem['used_mb']}MB;;;0;{mem['total_mb']}",
            f"'mem_free_mb'={mem['free_mb']}MB;;;0;{mem['total_mb']}",
        ]
        status_lines.append(
            f"RAM: {mem['used_pct']}% used ({mem['used_mb']}MB / {mem['total_mb']}MB)"
        )

    # --- CPU Load ---
    cpu = get_cpu_data(args)
    if cpu["load1"] > 0 or cpu["load5"] > 0:
        perfdata_parts += [
            f"'cpu_load1'={cpu['load1']};;;0",
            f"'cpu_load5'={cpu['load5']};;;0",
            f"'cpu_load15'={cpu['load15']};;;0",
        ]
        status_lines.append(
            f"CPU: {cpu['load1']} {cpu['load5']} {cpu['load15']} (1/5/15min)"
        )

    # --- Interface Traffic ---
    # Byte counters use the Nagios 'c' (counter) UOM so downstream graphers
    # compute proper bytes/sec rates instead of treating them as gauges.
    interfaces = get_interface_data(args)
    for iface in interfaces:
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', iface["name"])
        perfdata_parts += [
            f"'{safe_name}_in_b'={iface['in_b']}c",
            f"'{safe_name}_out_b'={iface['out_b']}c",
        ]
    if interfaces:
        up_ifaces   = [i["name"] for i in interfaces if i["status"] == "up"]
        down_ifaces = [i["name"] for i in interfaces if i["status"] == "down"]
        iface_msg   = f"UP: {', '.join(up_ifaces)}"
        if down_ifaces:
            iface_msg += f" | DOWN: {', '.join(down_ifaces)}"
        status_lines.append(f"Interfaces: {iface_msg}")

    # --- Disk Temperatures ---
    disks = get_disk_temps(args)
    for d in disks:
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', d["name"])
        perfdata_parts.append(f"'temp_{safe_name}'={d['temp_c']}C;;;0;70")
    if disks:
        temp_summary = ", ".join(f"{d['name']}:{d['temp_c']}°C" for d in disks)
        status_lines.append(f"Disk Temps: {temp_summary}")

    # --- Fail-safe: surface UNKNOWN if SNMP returned nothing at all ---
    if not status_lines and not perfdata_parts:
        print("UNKNOWN - No data collected via SNMP. "
              "Check connectivity, credentials, and MIB availability.")
        sys.exit(EXIT_UNKNOWN)

    # --- Output ---
    perfdata = " ".join(perfdata_parts)
    status   = " | ".join(status_lines)
    print(f"OK - {status} | {perfdata}")
    sys.exit(EXIT_OK)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="check_truenas.py - TrueNAS SNMP monitor for Icinga2/Nagios",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Target
    parser.add_argument("-H", "--host",      required=True,  help="TrueNAS hostname or IP")
    parser.add_argument("-t", "--type",      required=True,  choices=["info", "health"],
                        help="Check type:\n  info   = informative, always OK, full perfdata\n  health = ZFS pool health, alerts on failure")
    parser.add_argument("--timeout",         type=int, default=10, help="SNMP timeout in seconds (default: 10)")
    parser.add_argument("--pool",            help="Specific pool name to check (health mode only, default: all non-boot pools)")
    parser.add_argument("--include-boot",    action="store_true", dest="include_boot",
                        help="Include boot pool in health and info checks (default: excluded in both)")

    # SNMPv2c
    snmp2 = parser.add_argument_group("SNMPv2c options")
    snmp2.add_argument("-C", "--community",  default="public", help="SNMP community string (default: public)")

    # SNMPv3
    snmp3 = parser.add_argument_group("SNMPv3 options")
    snmp3.add_argument("--snmp-version",     dest="snmp_version", default="2c", choices=["2c", "3"],
                       help="SNMP version (default: 2c)")
    snmp3.add_argument("--v3-user",          help="SNMPv3 username")
    snmp3.add_argument("--v3-level",         help="SNMPv3 security level (noAuthNoPriv|authNoPriv|authPriv)")
    snmp3.add_argument("--v3-auth-proto",    help="SNMPv3 auth protocol (MD5|SHA)")
    snmp3.add_argument("--v3-auth",          help="SNMPv3 auth password")
    snmp3.add_argument("--v3-priv-proto",    help="SNMPv3 priv protocol (DES|AES)")
    snmp3.add_argument("--v3-priv",          help="SNMPv3 priv password")

    args = parser.parse_args()

    # Validate SNMPv3
    if args.snmp_version == "3" and not args.v3_user:
        parser.error("--v3-user is required when using SNMPv3")

    return args

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    if args.type == "health":
        check_health(args)
    elif args.type == "info":
        check_info(args)

if __name__ == "__main__":
    main()
