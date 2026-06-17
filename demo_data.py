"""Fixture data for the BeaconButty demo Flask app.

Every page renders pre-baked data from this module. Nothing here talks to
Zeek / RITA / ClickHouse / Suricata — the file is the contract.

Conventions:
  * LAN IPs stay in 192.168.50.0/24 (matches production schema).
  * External IPs use RFC 5737 doc ranges (203.0.113.0/24, 198.51.100.0/24)
    OR well-known public CDN/SaaS IPs (1.1.1.1, 8.8.8.8 etc.) where
    a recognisable name helps the demo tell a story.
  * MAC addresses use the 02:xx locally-administered range for examples.
  * Device labels are generic: "Laptop A", "IoT-Camera-1", "Phone-A", etc.
  * Timestamps are derived from a fixed reference REF_DT (2026-06-17 14:30 UTC)
    so the demo always looks identical — never use datetime.now().
"""

from datetime import datetime, timedelta, timezone

# ── Reference time anchor ─────────────────────────────────────────────────────
REF_DT = datetime(2026, 6, 17, 14, 30, 0, tzinfo=timezone.utc)
REF_DATE = REF_DT.date()
REF_ISO = REF_DT.strftime("%Y-%m-%d %H:%M:%S")
REF_DATE_STR = REF_DT.strftime("%Y-%m-%d")
REF_TS = int(REF_DT.timestamp())


def _iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _date(dt):
    return dt.strftime("%Y-%m-%d")


# ─────────────────────────────────────────────────────────────────────────────
# Threat-intel fixtures (reused across panels)
# ─────────────────────────────────────────────────────────────────────────────

INTEL_HIGH_C2 = {
    "abuseipdb": {
        "score": 92, "total_reports": 47,
        "last_reported": REF_DATE_STR + "T08:11:00",
        "usage_type": "Data Center/Web Hosting/Transit",
        "isp": "ExampleHost LLC", "domain": "examplehost.example",
    },
    "shodan": {
        "tags": ["malware", "compromised"],
        "vulns": ["CVE-2024-12345"],
        "ports": [22, 80, 443, 8080, 9001],
        "hostnames": ["c2.evil-c2.test"],
    },
    "spamhaus": {"drop": True, "sbl": "SBL999999"},
    "tor": {"exit": False},
}

INTEL_TOR = {
    "abuseipdb": {"score": 60, "total_reports": 18,
                  "last_reported": REF_DATE_STR + "T03:22:00",
                  "usage_type": "Tor Exit", "isp": "Tor Project"},
    "shodan": {"tags": ["tor"], "ports": [9001, 9030]},
    "spamhaus": {"drop": False},
    "tor": {"exit": True},
}

INTEL_CLEAN_CDN = {
    "abuseipdb": {"score": 0, "total_reports": 0,
                  "usage_type": "Content Delivery Network",
                  "isp": "Cloudflare, Inc.", "domain": "cloudflare.com"},
    "shodan": {"tags": ["cdn", "cloud"], "ports": [80, 443],
               "hostnames": ["one.one.one.one"]},
    "spamhaus": {"drop": False},
    "tor": {"exit": False},
}

INTEL_MEDIUM = {
    "abuseipdb": {"score": 42, "total_reports": 11,
                  "last_reported": REF_DATE_STR + "T01:05:00",
                  "usage_type": "Data Center/Web Hosting/Transit",
                  "isp": "Example Hosting Ltd"},
    "shodan": {"tags": ["cloud"], "ports": [22, 443]},
    "spamhaus": {"drop": False},
    "tor": {"exit": False},
}


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD = {
    "now": REF_ISO + " UTC",
    "eth_ip": "192.168.50.1",
    "ts_ip": "100.64.0.12",
    "pcap_active": 1,
    "stats": {
        "temp_c": 54.2,
        "cpu_pct": 18,
        "mem_pct": 36,
        "mem_used_mb": 2880,
        "mem_total_mb": 8000,
        "disk_pct": 47,
        "disk_free_gb": 252,
        "log2ram_pct": 41,
        "log2ram_used_mb": 210,
        "log2ram_total_mb": 512,
        "uptime": "23d 4h",
        "pi_fan_on": False,
        "pironman_fan_on": True,
        "pironman_fan_manual": False,
    },
    "beacon_count": 4,
    "suricata_counts": {1: 1, 2: 3, 3: 12, 4: 5},
    "network": {
        "total": 6,
        "ja4": 1,
        "l2": 1,
        "new_beacons": 2,
        "tls": 1,
        "dns": 1,
    },
    "slow": {"eligible": 2, "total": 7},
    "health": {
        "exit_code": 1,
        "last_check": REF_ISO + " UTC",
        "failures": [],
        "warnings": [
            "Disk usage 47% on / — within range but trending up.",
            "ClickHouse log size 480 MB — housekeeping due.",
        ],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# BEACONS — heaviest fixture
# ─────────────────────────────────────────────────────────────────────────────

def _beacon(dest, score, conns, svc="443:tcp:ssl", severity=None,
            fqdn=None, raw_dst=None, intel=None, enrich_name=None,
            enrich_source=None, enrich_when_days=None, dst_org=None):
    if severity is None:
        if score >= 0.80:
            severity = "High"
        elif score >= 0.50:
            severity = "Medium"
        elif score >= 0.30:
            severity = "Low"
        else:
            severity = "None"
    return {
        "dest": dest,
        "raw_dst": raw_dst or dest,
        "fqdn": fqdn or (dest if not dest.replace(".", "").isdigit() else ""),
        "score": score,
        "conns": conns,
        "svc": svc,
        "severity": severity,
        "intel": intel,
        "enrich_name": enrich_name,
        "enrich_source": enrich_source,
        "enrich_when_days": enrich_when_days,
        "dst_org": dst_org,
    }


_DEV_LAPTOP_A_HIGH = [
    _beacon("evil-c2.test", 0.96, 288, fqdn="evil-c2.test",
            intel=INTEL_HIGH_C2,
            dst_org="ExampleHost LLC"),
    _beacon("203.0.113.99", 0.91, 144, svc="443:tcp:ssl",
            raw_dst="203.0.113.99",
            intel=INTEL_HIGH_C2,
            enrich_name="api.suspicious.test", enrich_source="ssl",
            enrich_when_days=0, dst_org="ExampleHost LLC"),
]
_DEV_LAPTOP_A_MED = [
    _beacon("telemetry.example.com", 0.62, 72, fqdn="telemetry.example.com",
            dst_org="Example Telemetry Co"),
]
_DEV_LAPTOP_A_LOW = [
    _beacon("ocsp.digicert.com", 0.42, 24, fqdn="ocsp.digicert.com",
            dst_org="DigiCert, Inc."),
    _beacon("clients3.google.com", 0.38, 18, fqdn="clients3.google.com",
            dst_org="Google LLC"),
]

_DEV_IOT_HIGH = [
    _beacon("203.0.113.45", 0.89, 432, svc="8883:tcp:mqtt",
            raw_dst="203.0.113.45",
            intel=INTEL_MEDIUM,
            enrich_name="mqtt.iot-vendor.test", enrich_source="dns",
            enrich_when_days=1, dst_org="Example IoT Cloud"),
]
_DEV_IOT_MED = [
    _beacon("198.51.100.20", 0.55, 96, raw_dst="198.51.100.20",
            dst_org="Example Cloud Storage"),
]

_DEV_PHONE_LOW = [
    _beacon("apple-push.apple.com.test", 0.45, 36,
            fqdn="apple-push.apple.com.test", dst_org="Apple Inc."),
    _beacon("graph.example.org", 0.39, 22, fqdn="graph.example.org",
            dst_org="Example Social Co"),
]

_DEV_NAS_LOW = [
    _beacon("update.example.net", 0.34, 12, fqdn="update.example.net",
            dst_org="Example Software Vendor"),
]


_LAPTOP_A_ALL = _DEV_LAPTOP_A_HIGH + _DEV_LAPTOP_A_MED + _DEV_LAPTOP_A_LOW
_IOT_ALL = _DEV_IOT_HIGH + _DEV_IOT_MED
_PHONE_ALL = list(_DEV_PHONE_LOW)
_NAS_ALL = list(_DEV_NAS_LOW)

_DEVICES = [
    {
        "label": "192.168.50.10 (Laptop A)",
        "high": len(_DEV_LAPTOP_A_HIGH),
        "med": len(_DEV_LAPTOP_A_MED),
        "low": len(_DEV_LAPTOP_A_LOW),
        "total": len(_LAPTOP_A_ALL),
        "max_score": 0.96,
        "top_dests": [(0.96, "evil-c2.test"), (0.91, "203.0.113.99"),
                      (0.62, "telemetry.example.com")],
        "high_beacons": _DEV_LAPTOP_A_HIGH,
        "med_beacons": _DEV_LAPTOP_A_MED,
        "low_beacons": _DEV_LAPTOP_A_LOW,
        "all_beacons": _LAPTOP_A_ALL,
    },
    {
        "label": "192.168.50.50 (IoT-Camera-1)",
        "high": len(_DEV_IOT_HIGH),
        "med": len(_DEV_IOT_MED),
        "low": 0,
        "total": len(_IOT_ALL),
        "max_score": 0.89,
        "top_dests": [(0.89, "mqtt.iot-vendor.test"),
                      (0.55, "198.51.100.20")],
        "high_beacons": _DEV_IOT_HIGH,
        "med_beacons": _DEV_IOT_MED,
        "low_beacons": [],
        "all_beacons": _IOT_ALL,
    },
    {
        "label": "192.168.50.80 (Phone-A)",
        "high": 0,
        "med": 0,
        "low": len(_DEV_PHONE_LOW),
        "total": len(_PHONE_ALL),
        "max_score": 0.45,
        "top_dests": [(0.45, "apple-push.apple.com.test"),
                      (0.39, "graph.example.org")],
        "high_beacons": [],
        "med_beacons": [],
        "low_beacons": _DEV_PHONE_LOW,
        "all_beacons": _PHONE_ALL,
    },
    {
        "label": "192.168.50.100 (NAS)",
        "high": 0,
        "med": 0,
        "low": 1,
        "total": 1,
        "max_score": 0.34,
        "top_dests": [(0.34, "update.example.net")],
        "high_beacons": [],
        "med_beacons": [],
        "low_beacons": _DEV_NAS_LOW,
        "all_beacons": _NAS_ALL,
    },
]


def _label_for(beacon_dict):
    for d in _DEVICES:
        if beacon_dict in d["all_beacons"]:
            return d["label"]
    return ""


_TOP_BEACONS = sorted(
    [b for dev in _DEVICES for b in dev["all_beacons"] if b["score"] >= 0.80],
    key=lambda b: -b["score"],
)
for _b in _TOP_BEACONS:
    _b["label"] = _label_for(_b)


_INVESTIGATE = [
    {
        "label": "192.168.50.10 (Laptop A)",
        "dest": "evil-c2.test",
        "dest_entries": [
            {"raw": "evil-c2.test", "enrich": None, "source": ""},
            {"raw": "203.0.113.99", "enrich": "api.suspicious.test",
             "source": "ssl"},
        ],
        "score": 0.96,
        "flag_type": "tor",
        "flag_str": "Tor exit node contact + Spamhaus DROP listed",
        "ja4": "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
        "ja4_count": 288,
        "ja4_label": "Sliver Agent",
        "ja4_src": "ja4plus-mapping",
        "ja4_threat": True,
    },
    {
        "label": "192.168.50.50 (IoT-Camera-1)",
        "dest": "mqtt.iot-vendor.test",
        "dest_entries": [],
        "score": 0.89,
        "flag_type": "icmp",
        "flag_str": "Periodic MQTT keepalive — verify against vendor docs",
        "ja4": "t13d2014h2_a09f3c8d1abc_111122223333",
        "ja4_count": 432,
        "ja4_label": "Example IoT Client",
        "ja4_src": "ja4plus-mapping",
        "ja4_threat": False,
    },
]

_SUPPRESSED_GROUPS = [
    {
        "rule": "*.awair.is",
        "rule_type": "domain",
        "reason": "Awair air quality monitor telemetry",
        "rows": [
            {"label": "192.168.50.160 (Awair)", "dest": "telemetry.awair.is",
             "score": 0.61, "severity": "Medium", "svc": "443:tcp:ssl",
             "intel": None},
            {"label": "192.168.50.160 (Awair)", "dest": "fw.awair.is",
             "score": 0.48, "severity": "Low", "svc": "443:tcp:ssl",
             "intel": None},
        ],
    },
    {
        "rule": "123:udp:ntp",
        "rule_type": "protocol",
        "reason": "NTP time sync",
        "rows": [
            {"label": "192.168.50.10 (Laptop A)", "dest": "pool.ntp.org",
             "score": 0.55, "severity": "Medium", "svc": "123:udp:ntp",
             "intel": None},
            {"label": "192.168.50.42 (Peloton)", "dest": "time.apple.com",
             "score": 0.40, "severity": "Low", "svc": "123:udp:ntp",
             "intel": None},
            {"label": "192.168.50.100 (NAS)", "dest": "time.google.com",
             "score": 0.38, "severity": "Low", "svc": "123:udp:ntp",
             "intel": None},
        ],
    },
]


def _date_groups_build():
    """Last 14 days, grouped into current week + last week."""
    current_dates = []
    older_dates = []
    for i in range(14):
        d = REF_DATE - timedelta(days=i)
        entry = (d.strftime("%Y-%m-%d"), 0)
        if i < 7:
            current_dates.append(entry)
        else:
            older_dates.append(entry)
    return [
        {"is_current": True, "label": "This week", "dates": current_dates},
        {"is_current": False, "label": "Last week", "dates": older_dates},
    ]


_DATE_GROUPS = _date_groups_build()
_DATE_LIST = [ds for g in _DATE_GROUPS for ds, _ in g["dates"]]

BEACON_DATA = {
    "date_range": f"{(REF_DATE - timedelta(days=2)).strftime('%Y-%m-%d')} → {REF_DATE_STR}",
    "total": sum(d["total"] for d in _DEVICES),
    "sev_counts": {
        "High": sum(d["high"] for d in _DEVICES),
        "Medium": sum(d["med"] for d in _DEVICES),
        "Low": sum(d["low"] for d in _DEVICES),
        "None": 0,
    },
    "suppressed": sum(len(g["rows"]) for g in _SUPPRESSED_GROUPS),
    "fp_count": 12,
    "devices": _DEVICES,
    "top_beacons": _TOP_BEACONS,
    "investigate": _INVESTIGATE,
    "suppressed_groups": _SUPPRESSED_GROUPS,
}

BEACONS = {
    "date_groups": _DATE_GROUPS,
    "date_list": _DATE_LIST,
    "selected_date": REF_DATE_STR,
    "beacon_data": BEACON_DATA,
    "top_beacons_label": "last 3 days",
}


# ─────────────────────────────────────────────────────────────────────────────
# SLOW_PAYLOAD — slow-cadence beacons
# ─────────────────────────────────────────────────────────────────────────────

def _slow_row(dst, dst_port, sni=None, http_host=None, days=7,
              conns_per_day=2, lan_talkers=1, modal_hour=3,
              hour_consistency=0.95, interval_cv=0.08,
              dst_org="Example Hosting Ltd", dst_cc="US",
              is_hyperscaler=False, alert_eligible=True,
              intel=None):
    return {
        "dst": dst,
        "dst_port": dst_port,
        "sni": sni,
        "http_host": http_host,
        "http_hosts": [http_host] if http_host else [],
        "http_useragent": None,
        "http_uri_sample": None,
        "http_method_mix": None,
        "days_seen": days,
        "conns_per_active_day": conns_per_day,
        "lan_talkers": lan_talkers,
        "modal_hour_utc": modal_hour,
        "hour_consistency": hour_consistency,
        "interval_cv": interval_cv,
        "dst_org": dst_org,
        "dst_cc": dst_cc,
        "is_hyperscaler": is_hyperscaler,
        "alert_eligible": alert_eligible,
        "intel": intel,
    }


_SLOW_GROUPS = [
    {
        "src": "192.168.50.10",
        "src_label": "192.168.50.10 (Laptop A)",
        "dst_count": 2,
        "count": 2,
        "eligible_count": 1,
        "rows": [
            _slow_row("203.0.113.77", 443, sni="beacon.suspicious.test",
                      days=12, conns_per_day=4, lan_talkers=1,
                      modal_hour=3, hour_consistency=0.97,
                      interval_cv=0.05,
                      dst_org="ExampleHost LLC", dst_cc="US",
                      is_hyperscaler=False, alert_eligible=True,
                      intel=INTEL_MEDIUM),
            _slow_row("198.51.100.40", 443,
                      sni="cdn.example-saas.test",
                      days=8, conns_per_day=3, lan_talkers=5,
                      modal_hour=2, hour_consistency=0.82,
                      interval_cv=0.34,
                      dst_org="Cloudflare, Inc.", dst_cc="US",
                      is_hyperscaler=True, alert_eligible=False),
        ],
    },
    {
        "src": "192.168.50.50",
        "src_label": "192.168.50.50 (IoT-Camera-1)",
        "dst_count": 3,
        "count": 3,
        "eligible_count": 1,
        "rows": [
            _slow_row("203.0.113.55", 8883,
                      http_host="mqtt.iot-vendor.test",
                      days=14, conns_per_day=6, lan_talkers=1,
                      modal_hour=4, hour_consistency=0.99,
                      interval_cv=0.03,
                      dst_org="Example IoT Cloud", dst_cc="US",
                      is_hyperscaler=False, alert_eligible=True),
            _slow_row("23.23.189.12", 33434,
                      days=10, conns_per_day=1, lan_talkers=2,
                      modal_hour=5, hour_consistency=0.78,
                      interval_cv=0.42,
                      dst_org="Amazon.com, Inc.", dst_cc="US",
                      is_hyperscaler=True, alert_eligible=False),
            _slow_row("198.51.100.66", 443,
                      sni="ota.iot-vendor.test",
                      days=6, conns_per_day=2, lan_talkers=1,
                      modal_hour=4, hour_consistency=0.91,
                      interval_cv=0.15,
                      dst_org="Example IoT Cloud", dst_cc="US",
                      is_hyperscaler=False, alert_eligible=False),
        ],
    },
    {
        "src": "192.168.50.100",
        "src_label": "192.168.50.100 (NAS)",
        "dst_count": 2,
        "count": 2,
        "eligible_count": 0,
        "rows": [
            _slow_row("8.8.8.8", 53,
                      days=14, conns_per_day=5, lan_talkers=8,
                      modal_hour=4, hour_consistency=0.72,
                      interval_cv=0.55,
                      dst_org="Google LLC", dst_cc="US",
                      is_hyperscaler=True, alert_eligible=False),
            _slow_row("1.1.1.1", 53,
                      days=14, conns_per_day=4, lan_talkers=8,
                      modal_hour=4, hour_consistency=0.68,
                      interval_cv=0.62,
                      dst_org="Cloudflare, Inc.", dst_cc="US",
                      is_hyperscaler=True, alert_eligible=False),
        ],
    },
]

SLOW_PAYLOAD = {
    "candidates": [r for g in _SLOW_GROUPS for r in g["rows"]],
    "groups": _SLOW_GROUPS,
    "generated_at": REF_ISO + " UTC",
    "window_days": 14,
    "thresholds": {
        "min_days_seen": 5,
        "max_conns_per_active_day": 6,
        "min_hour_consistency": 0.70,
    },
    "eligible_total": sum(g["eligible_count"] for g in _SLOW_GROUPS),
}


# ─────────────────────────────────────────────────────────────────────────────
# SURICATA
# ─────────────────────────────────────────────────────────────────────────────

def _sig(rule, priority, count, unique_srcs=1, last_seen=None):
    return {
        "rule": rule,
        "priority": priority,
        "count": count,
        "unique_srcs": unique_srcs,
        "last_seen": last_seen or REF_ISO,
    }


_SIG_LIST = [
    _sig("ET TROJAN Suspicious User-Agent (BackdoorAgent)", 1, 4, 1,
         REF_ISO),
    _sig("ET POLICY DNS Query to .onion proxy Domain", 2, 7, 2,
         _iso(REF_DT - timedelta(minutes=12))),
    _sig("ET INFO Suspicious User-Agent (curl-from-script)", 2, 3, 1,
         _iso(REF_DT - timedelta(hours=1))),
    _sig("ET POLICY HTTP traffic on port 443 (POST)", 2, 5, 2,
         _iso(REF_DT - timedelta(hours=2))),
    _sig("ET SCAN Behavioral Unusually fast Terminal Server Traffic", 3, 7, 3,
         _iso(REF_DT - timedelta(hours=3))),
    _sig("ET INFO Microsoft Windows CryptoAPI Update", 3, 5, 4,
         _iso(REF_DT - timedelta(hours=4))),
    _sig("ET POLICY External IP Lookup Service (ipify.org)", 4, 5, 2,
         _iso(REF_DT - timedelta(hours=5))),
]

_LAN_ROWS = [
    {
        "lan_label": "192.168.50.10 (Laptop A)",
        "alerts": [
            {"ext_ip": "203.0.113.99", "priority": 1,
             "rule": "ET TROJAN Suspicious User-Agent (BackdoorAgent)",
             "count": 4, "ext_intel": INTEL_HIGH_C2,
             "ext_enrich": "api.suspicious.test", "ext_source": "ssl"},
            {"ext_ip": "203.0.113.45", "priority": 2,
             "rule": "ET POLICY HTTP traffic on port 443 (POST)",
             "count": 2, "ext_intel": INTEL_MEDIUM,
             "ext_enrich": None, "ext_source": None},
            {"ext_ip": "198.51.100.30", "priority": 3,
             "rule": "ET INFO Microsoft Windows CryptoAPI Update",
             "count": 1, "ext_intel": None,
             "ext_enrich": None, "ext_source": None},
        ],
    },
    {
        "lan_label": "192.168.50.50 (IoT-Camera-1)",
        "alerts": [
            {"ext_ip": "203.0.113.45", "priority": 2,
             "rule": "ET POLICY DNS Query to .onion proxy Domain",
             "count": 3, "ext_intel": INTEL_MEDIUM,
             "ext_enrich": "mqtt.iot-vendor.test", "ext_source": "dns"},
        ],
    },
    {
        "lan_label": "192.168.50.80 (Phone-A)",
        "alerts": [
            {"ext_ip": "8.8.8.8", "priority": 4,
             "rule": "ET POLICY External IP Lookup Service (ipify.org)",
             "count": 5, "ext_intel": INTEL_CLEAN_CDN,
             "ext_enrich": "dns.google", "ext_source": "dns"},
        ],
    },
]

_UNRESOLVED = [
    {
        "src_ip": "203.0.113.5",
        "dst_ip": "192.168.50.1",
        "priority": 3,
        "rule": "ET SCAN Behavioral Unusually fast Terminal Server Traffic",
        "src_intel": INTEL_MEDIUM, "dst_intel": None,
        "src_enrich": None, "src_source": None,
        "dst_enrich": "bb0", "dst_source": "manual",
    },
]

_TREND_DATA = []
_TREND_COUNTS = [4, 8, 12, 6, 10, 14, 19]
for i in range(7):
    d = REF_DATE - timedelta(days=6 - i)
    _TREND_DATA.append({
        "date": d.strftime("%Y-%m-%d"),
        "count": _TREND_COUNTS[i],
        "no_data": False,
    })

_HOURLY_DATA = []
for h in range(24):
    if h == 3:
        c = 4
    elif h == 14:
        c = 6
    elif h in (9, 10, 11, 15, 16):
        c = 3
    elif h in (8, 13, 17, 19):
        c = 2
    elif h in (1, 2, 4, 5):
        c = 1
    else:
        c = 0
    _HOURLY_DATA.append({"hour": h, "count": c})

_CATEGORY_BREAKDOWN = [
    {"cat": "ET POLICY", "count": 15},
    {"cat": "ET INFO", "count": 8},
    {"cat": "ET SCAN", "count": 7},
    {"cat": "ET TROJAN", "count": 4},
    {"cat": "ET MALWARE", "count": 2},
]

_OFFENDERS = [
    {
        "ip_display": "203.0.113.99",
        "rule_count": 3,
        "rules": [
            "ET TROJAN Suspicious User-Agent (BackdoorAgent)",
            "ET POLICY HTTP traffic on port 443 (POST)",
            "ET SCAN Behavioral Unusually fast Terminal Server Traffic",
        ],
    },
]

_EVE_ENRICHED = {
    "ET TROJAN Suspicious User-Agent (BackdoorAgent)": {
        "http": {
            "hostname": "evil-c2.test",
            "url": "/beacon?id=ABC123",
            "user_agent": "Mozilla/5.0 (compatible; BackdoorAgent/1.0)",
        },
        "dns_query": None,
        "tls_sni": None,
    },
    "ET POLICY DNS Query to .onion proxy Domain": {
        "http": None,
        "dns_query": "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion.example",
        "tls_sni": None,
    },
    "ET POLICY HTTP traffic on port 443 (POST)": {
        "http": {
            "hostname": "203.0.113.45",
            "url": "/api/upload",
            "user_agent": "curl/8.4.0",
        },
        "dns_query": None,
        "tls_sni": None,
    },
}

_TREND_DETAILS = {}
for day in _TREND_DATA:
    _TREND_DETAILS[day["date"]] = [
        {
            "time": "03:14:22",
            "priority": 1,
            "rule": "ET TROJAN Suspicious User-Agent (BackdoorAgent)",
            "src": "192.168.50.10",
            "dst": "203.0.113.99",
        },
        {
            "time": "14:08:11",
            "priority": 2,
            "rule": "ET POLICY DNS Query to .onion proxy Domain",
            "src": "192.168.50.50",
            "dst": "203.0.113.45",
        },
    ]

SURICATA = {
    "sig_list": _SIG_LIST,
    "lan_rows": _LAN_ROWS,
    "unresolved": _UNRESOLVED,
    "total_alerts": sum(s["count"] for s in _SIG_LIST),
    "extras": {
        "cross_ref": [
            {"label": "192.168.50.10 (Laptop A)"},
            {"label": "192.168.50.50 (IoT-Camera-1)"},
        ],
        "eve_enriched": _EVE_ENRICHED,
        "category_breakdown": _CATEGORY_BREAKDOWN,
        "trend_data": _TREND_DATA,
        "hourly_data": _HOURLY_DATA,
        "offenders": _OFFENDERS,
        "trend_details": _TREND_DETAILS,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# RULES
# ─────────────────────────────────────────────────────────────────────────────

RULES = {
    "local_rules": [
        {
            "sid": "1000001", "enabled": True, "action": "alert",
            "msg": "BB-LOCAL Inbound SSH from non-LAN",
            "classtype": "attempted-admin",
            "raw": 'alert tcp !192.168.0.0/16 any -> $HOME_NET 22 '
                   '(msg:"BB-LOCAL Inbound SSH from non-LAN"; '
                   'classtype:attempted-admin; sid:1000001; rev:1;)',
        },
        {
            "sid": "1000002", "enabled": True, "action": "alert",
            "msg": "BB-LOCAL DNS Query to evil-c2.test",
            "classtype": "domain-c2",
            "raw": 'alert dns any any -> any any '
                   '(msg:"BB-LOCAL DNS Query to evil-c2.test"; '
                   'dns.query; content:"evil-c2.test"; nocase; '
                   'classtype:domain-c2; sid:1000002; rev:1;)',
        },
        {
            "sid": "1000003", "enabled": False, "action": "drop",
            "msg": "BB-LOCAL Block Tor exit traffic (sample)",
            "classtype": "policy-violation",
            "raw": 'drop tcp $HOME_NET any -> any any '
                   '(msg:"BB-LOCAL Block Tor exit traffic (sample)"; '
                   'classtype:policy-violation; sid:1000003; rev:1;)',
        },
    ],
    "et_stats": {
        "count": 47823,
        "size_mb": 18.4,
        "modified": REF_DATE_STR,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK_INTEL
# ─────────────────────────────────────────────────────────────────────────────

NETWORK_INTEL = {
    "ja4_threats": [
        {
            "label": "192.168.50.10 (Laptop A)",
            "match": "Sliver Agent",
            "count": 288,
            "ja4": "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
            "source": "ja4plus-mapping",
        },
    ],
    "l2_anomalies": [
        {
            "severity": "warning",
            "kind": "mac_change",
            "ip": "192.168.50.80",
            "label": "192.168.50.80 (Phone-A)",
            "mac": "02:00:00:00:00:08, 02:00:00:00:00:09",
            "detail": "2 MACs claimed this IP today (likely randomised MAC)",
        },
    ],
    "tls_anomalies": [
        {
            "src_label": "192.168.50.10 (Laptop A)",
            "entities": [
                {
                    "org": "ExampleHost LLC",
                    "ips": ["203.0.113.99"],
                    "issue": "self-signed",
                    "count": 12,
                },
            ],
        },
    ],
    "dns_anomalies": [
        {
            "src_label": "192.168.50.10 (Laptop A)",
            "total": 1840,
            "nxdomain": 612,
            "nxdomain_pct": 33,
            "flag": "both",
            "examples": [
                ("x7f3k2m9a2.test", 4.21),
                ("p8q1w3e5r7.test", 4.17),
                ("z9y8x7v6u5.test", 4.10),
            ],
        },
    ],
    "new_beacons": [
        {
            "src_label": "192.168.50.10 (Laptop A)",
            "group_first": True,
            "group_size": 2,
            "severity": "High",
            "dest": "evil-c2.test",
            "dest_key": "evil-c2.test",
            "dest_enrich": None,
            "score": 0.96,
            "svc": "443:tcp:ssl",
            "first_seen": REF_DATE_STR,
            "dst_org": "ExampleHost LLC",
        },
        {
            "src_label": "192.168.50.10 (Laptop A)",
            "group_first": False,
            "group_size": 2,
            "severity": "High",
            "dest": "203.0.113.99",
            "dest_key": "203.0.113.99",
            "dest_enrich": {
                "name": "api.suspicious.test",
                "source": "ssl",
                "when_days": 0,
                "intel": INTEL_HIGH_C2,
            },
            "score": 0.91,
            "svc": "443:tcp:ssl",
            "first_seen": REF_DATE_STR,
            "dst_org": "ExampleHost LLC",
        },
    ],
    "ja4_inventory": [
        {
            "label": "192.168.50.10 (Laptop A)",
            "n_unique": 14,
            "n_total": 1240,
            "n_new_today": 2,
            "outlier": False,
            "threat": True,
            "more": 9,
            "top": [
                ("t13d1517h2_8daaf6152771_b1ff8ab2d16f", 288, False,
                 "Sliver Agent", "ja4plus-mapping", True),
                ("t13d1715h2_5b57614c22b0_eeebfe0fad9f", 412, False,
                 "Chrome 124", "ja4plus-mapping", False),
                ("t13d2014h2_a09f3c8d1abc_111122223333", 88, True,
                 None, None, False),
                ("t13d1716h2_5b57614c22b0_3d83d3a3f3a3", 156, False,
                 "Firefox 126", "ja4plus-mapping", False),
                ("t13d211200_aabbccdd1122_001122334455", 22, True,
                 None, None, False),
            ],
            "threat_details": [
                {"label": "Sliver Agent",
                 "ja4": "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
                 "count": 288},
            ],
        },
        {
            "label": "192.168.50.50 (IoT-Camera-1)",
            "n_unique": 1,
            "n_total": 432,
            "n_new_today": 0,
            "outlier": True,
            "threat": False,
            "more": 0,
            "top": [
                ("t13d2014h2_a09f3c8d1abc_111122223333", 432, False,
                 "Example IoT Client", "ja4plus-mapping", False),
            ],
            "threat_details": [],
        },
        {
            "label": "192.168.50.80 (Phone-A)",
            "n_unique": 8,
            "n_total": 612,
            "n_new_today": 0,
            "outlier": False,
            "threat": False,
            "more": 3,
            "top": [
                ("t13d1715h2_5b57614c22b0_eeebfe0fad9f", 245, False,
                 "Safari 18", "ja4plus-mapping", False),
                ("t13d211200_aabbccdd1122_551122334466", 132, False,
                 "URLSession (iOS)", "ja4plus-mapping", False),
                ("t13d301400_22aabbcc3344_998877665544", 88, False,
                 "WhatsApp", "ja4plus-mapping", False),
            ],
            "threat_details": [],
        },
    ],
    "exfil": [
        {
            "src_label": "192.168.50.100 (NAS)",
            "total_mb": 142,
            "conns": 24,
            "top_dst": "backup.example.net",
        },
        {
            "src_label": "192.168.50.20 (Workstation B)",
            "total_mb": 58,
            "conns": 12,
            "top_dst": "203.0.113.200",
        },
    ],
    "night": [
        {
            "src_label": "192.168.50.10 (Laptop A)",
            "conns": 86,
            "mb": 12,
            "unique_dsts": 4,
        },
        {
            "src_label": "192.168.50.50 (IoT-Camera-1)",
            "conns": 144,
            "mb": 3,
            "unique_dsts": 2,
        },
    ],
    "weird": [
        {
            "name": "active_connection_reuse",
            "count": 18,
            "src_count": 2,
            "srcs": "192.168.50.10, 192.168.50.100",
            "addl": "TCP connection reused before old FIN/RST",
        },
        {
            "name": "dns_unmatched_reply",
            "count": 6,
            "src_count": 1,
            "srcs": "192.168.50.80",
            "addl": "DNS reply with no matching query",
        },
    ],
    "persistence": [
        {
            "src_label": "192.168.50.10 (Laptop A)",
            "dest": "evil-c2.test",
            "dest_key": "evil-c2.test",
            "dest_enrich": None,
            "days": 12,
            "latest_date": REF_DATE_STR,
            "score": 0.96,
            "dst_org": "ExampleHost LLC",
        },
        {
            "src_label": "192.168.50.50 (IoT-Camera-1)",
            "dest": "mqtt.iot-vendor.test",
            "dest_key": "mqtt.iot-vendor.test",
            "dest_enrich": {"name": "mqtt.iot-vendor.test", "source": "dns",
                            "when_days": 0, "intel": None},
            "days": 14,
            "latest_date": REF_DATE_STR,
            "score": 0.89,
            "dst_org": "Example IoT Cloud",
        },
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# ASSETS
# ─────────────────────────────────────────────────────────────────────────────

_ASSETS_LIST = [
    ("192.168.50.1", {
        "hostname": "bb0", "hostname_source": "manual",
        "os": "Raspberry Pi OS Lite 64-bit",
        "mac": "02:00:00:00:00:01", "mac_vendor": "Raspberry Pi (demo)",
        "open_ports": ["22", "53", "80", "443"],
        "last_seen": REF_DATE_STR, "source": "manual",
        "ghost": False,
    }),
    ("192.168.50.10", {
        "hostname": "laptop-a", "hostname_source": "dhcp",
        "os": "macOS 15.4",
        "mac": "02:00:00:00:00:10", "mac_vendor": "Apple (demo)",
        "open_ports": [],
        "last_seen": REF_DATE_STR, "source": "dhcp",
        "ghost": False,
    }),
    ("192.168.50.20", {
        "hostname": "workstation-b", "hostname_source": "dhcp",
        "os": "Linux 6.8",
        "mac": "02:00:00:00:00:20", "mac_vendor": "Generic (demo)",
        "open_ports": ["22"],
        "last_seen": REF_DATE_STR, "source": "dhcp",
        "ghost": False,
    }),
    ("192.168.50.42", {
        "hostname": "peloton", "hostname_source": "dhcp",
        "os": None,
        "mac": "02:00:00:00:00:42", "mac_vendor": "Peloton (demo)",
        "open_ports": [],
        "last_seen": REF_DATE_STR, "source": "dhcp",
        "ghost": False,
    }),
    ("192.168.50.50", {
        "hostname": "iot-camera-1", "hostname_source": "dhcp",
        "os": None,
        "mac": "02:00:00:00:00:50", "mac_vendor": "IoT Vendor (demo)",
        "open_ports": ["554"],
        "last_seen": REF_DATE_STR, "source": "dhcp",
        "ghost": False,
    }),
    ("192.168.50.80", {
        "hostname": "phone-a", "hostname_source": "dhcp",
        "os": "iOS (demo)",
        "mac": "02:00:00:00:00:80", "mac_vendor": "Apple (demo)",
        "open_ports": [],
        "last_seen": REF_DATE_STR, "source": "dhcp",
        "ghost": False,
    }),
    ("192.168.50.100", {
        "hostname": "nas", "hostname_source": "manual",
        "os": "Linux 6.6",
        "mac": "02:00:00:00:01:00", "mac_vendor": "Synology (demo)",
        "open_ports": ["22", "80", "443", "5000", "5001"],
        "last_seen": REF_DATE_STR, "source": "dhcp",
        "ghost": False,
    }),
    ("192.168.50.160", {
        "hostname": "awair", "hostname_source": "dhcp",
        "os": None,
        "mac": "02:00:00:00:01:60", "mac_vendor": "Awair (demo)",
        "open_ports": [],
        "last_seen": REF_DATE_STR, "source": "dhcp",
        "ghost": False,
    }),
    ("192.168.50.117", {
        "hostname": None, "hostname_source": None,
        "os": None,
        "mac": "02:00:00:00:01:17", "mac_vendor": "Unknown (demo)",
        "open_ports": [],
        "last_seen": _date(REF_DT - timedelta(days=4)), "source": "ghost",
        "ghost": True, "days_ago": 4,
    }),
]

_JA4_SUMMARIES = {
    "192.168.50.10": {
        "n_total": 14, "n_today": 11, "n_new_today": 2,
        "modal": "t13d1715h2_5b57614c22b0_eeebfe0fad9f",
        "modal_count": 412, "first_seen": REF_DATE_STR,
        "client_label": "Sliver Agent",
        "client_threat": True,
        "client_src": "ja4plus-mapping",
        "any_threat": True,
        "threat_details": [
            {"label": "Sliver Agent",
             "ja4": "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
             "last_seen": REF_DATE_STR},
        ],
    },
    "192.168.50.80": {
        "n_total": 8, "n_today": 6, "n_new_today": 0,
        "modal": "t13d1715h2_5b57614c22b0_eeebfe0fad9f",
        "modal_count": 245, "first_seen": _date(REF_DT - timedelta(days=10)),
        "client_label": "Safari 18",
        "client_threat": False,
        "client_src": "ja4plus-mapping",
        "any_threat": False,
        "threat_details": [],
    },
    "192.168.50.50": {
        "n_total": 1, "n_today": 1, "n_new_today": 0,
        "modal": "t13d2014h2_a09f3c8d1abc_111122223333",
        "modal_count": 432, "first_seen": _date(REF_DT - timedelta(days=30)),
        "client_label": "Example IoT Client",
        "client_threat": False,
        "client_src": "ja4plus-mapping",
        "any_threat": False,
        "threat_details": [],
    },
}

ASSETS = {
    "assets": _ASSETS_LIST,
    "fp_macs": {"02:00:00:00:01:60", "02:00:00:00:00:42"},
    "ja4_summaries": _JA4_SUMMARIES,
    "ja4_threat_fade_days": 14,
}


# ─────────────────────────────────────────────────────────────────────────────
# FPS
# ─────────────────────────────────────────────────────────────────────────────

FPS = {
    "rows": [
        {"mac": "02:00:00:00:01:60", "ip": "192.168.50.160",
         "label": "192.168.50.160 (Awair)",
         "reason": "Awair air quality monitor — ICMP telemetry"},
        {"mac": "02:00:00:00:00:42", "ip": "192.168.50.42",
         "label": "192.168.50.42 (Peloton)",
         "reason": "Peloton bike — normal telemetry"},
    ],
    "domain_rows": [
        {"pattern": "*.apple.com",
         "reason": "Apple CDN"},
        {"pattern": "*.icloud.com",
         "reason": "iCloud sync — known SaaS"},
        {"pattern": "*.awair.is",
         "reason": "Awair telemetry"},
        {"pattern": "*.windowsupdate.com",
         "reason": "Windows Update CDN"},
        {"pattern": "ocsp.digicert.com",
         "reason": "OCSP — every TLS client hits this"},
    ],
    "protocol_rows": [
        {"svc": "123:udp:ntp", "reason": "NTP time sync"},
        {"svc": "5353:udp:mdns", "reason": "mDNS service discovery"},
        {"svc": "67:udp:dhcp", "reason": "DHCP"},
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────

_HEALTH_REPORT = {
    "timestamp": REF_ISO + " UTC",
    "failures": 0,
    "warnings": 2,
    "sections": [
        {
            "name": "Services",
            "checks": [
                {"status": "ok", "message": "zeek.service active"},
                {"status": "ok", "message": "clickhouse-server.service active"},
                {"status": "ok", "message": "suricata.service active"},
                {"status": "ok", "message": "dnsmasq.service active"},
                {"status": "ok", "message": "bb-graphs.service active"},
                {"status": "ok", "message": "bb-watchdog.service active"},
            ],
        },
        {
            "name": "Network",
            "checks": [
                {"status": "ok", "message": "WAN reachable (ping 1.1.1.1 OK)"},
                {"status": "ok", "message": "DNS resolving (dig example.com OK)"},
                {"status": "ok", "message": "Zeek capturing on eth1"},
            ],
        },
        {
            "name": "Storage",
            "checks": [
                {"status": "warn",
                 "message": "Disk usage 47% on / — trending up"},
                {"status": "ok",
                 "message": "ClickHouse data 18.4 GB on /var/lib/clickhouse"},
                {"status": "warn",
                 "message": "ClickHouse log size 480 MB — housekeeping due"},
            ],
        },
        {
            "name": "Pipelines",
            "checks": [
                {"status": "ok",
                 "message": "Last RITA import 14 min ago"},
                {"status": "ok",
                 "message": "Last daily report at 07:00 UTC"},
                {"status": "ok",
                 "message": "Suricata rules last updated " + REF_DATE_STR},
            ],
        },
    ],
}

_CERT = {
    "subject": "demo.local",
    "issuer": "Let's Encrypt",
    "issued": _date(REF_DT - timedelta(days=19)),
    "expires": _date(REF_DT + timedelta(days=71)),
    "days_remaining": 71,
}

_GATE_STATS = {
    "slow_cadence": {
        "ts": _iso(REF_DT - timedelta(minutes=12)),
        "fired": 1,
        "gated": {"hyperscaler": 4, "shared_lan": 2},
    },
    "daily_summary": {
        "ts": _iso(REF_DT.replace(hour=7, minute=0, second=0)),
        "fired": {"high_score_beacon": 2, "persistent_beacon": 1},
        "gated": {
            "high_score_beacon": {"hyperscaler": 3, "shared_lan": 1},
            "persistent_beacon": {"hyperscaler": 1, "shared_lan": 0},
        },
    },
    "new_device": {
        "ts": _iso(REF_DT - timedelta(hours=2)),
        "fired": 0,
        "gated": {"mac_randomised": 4},
    },
}

TEAMS_DETECTOR_CONFIG = {
    "max_duration_hours": 6.0,
    "min_kbps": 5,
    "min_flow_seconds": 600,
}

TEAMS_DETECTOR_REPORT = {
    "generated": _iso(REF_DT - timedelta(minutes=8)),
    "flows_scanned": 142,
    "cidr_version": "2026-06-15",
    "findings": [
        {
            "src": "192.168.50.20",
            "dst": "52.114.132.46",
            "dst_port": 3478,
            "signals": ["new-JA4", "long-flow"],
            "duration_h": 7.4,
            "kbps": 3,
        },
        {
            "src": "192.168.50.80",
            "dst": "52.114.132.55",
            "dst_port": 3478,
            "signals": ["long-flow"],
            "duration_h": 6.1,
            "kbps": 14,
        },
    ],
}

ALERT_CONFIG = {
    "service_down": True,
    "disk_critical": True,
    "high_score_beacon": True,
    "persistent_beacon": True,
    "threat_intel_hit": True,
    "tor_contact": True,
    "suricata_p1_lan": True,
    "suricata_p1_repeated": True,
    "new_device": True,
    "slow_cadence_digest": True,
    "health_check_fail": True,
    "sustained_high_cpu": True,
    "teams_relay_anomaly": True,
}

HEALTH = {
    "report": _HEALTH_REPORT,
    "error": None,
    "alert_config": ALERT_CONFIG,
    "cert": _CERT,
    "gate_stats": _GATE_STATS,
    "teams_detector_config": TEAMS_DETECTOR_CONFIG,
    "teams_detector_report": TEAMS_DETECTOR_REPORT,
}


# ─────────────────────────────────────────────────────────────────────────────
# BACKUP
# ─────────────────────────────────────────────────────────────────────────────

def _make_backups():
    backups = []
    for i in range(14):
        d = REF_DT - timedelta(days=i)
        backups.append({
            "filename": f"config-{d.strftime('%Y-%m-%d')}.tar.gz",
            "date": d.strftime("%Y-%m-%d"),
            "mtime": d.strftime("%H:%M"),
            "size": "1.4 MB",
        })
    return backups


_BACKUPS = _make_backups()

_BACKUP_GROUPS = [
    {
        "is_current": True,
        "label": "This week",
        "entries": _BACKUPS[:7],
    },
    {
        "is_current": False,
        "label": "Last week",
        "entries": _BACKUPS[7:],
    },
]

_ARCHIVES = [
    {
        "filename": f"archive-{_date(REF_DT - timedelta(days=i*7))}.tar.gz",
        "mtime": (REF_DT - timedelta(days=i*7)).strftime("%H:%M"),
        "size": f"{18 + i}.4 GB",
    }
    for i in range(4)
]

BACKUP = {
    "backups": _BACKUPS,
    "backup_groups": _BACKUP_GROUPS,
    "archives": _ARCHIVES,
    "usb_drives": [
        {"name": "sda", "path": "/dev/sda", "size": "32 GB",
         "label": "BB-CLONE", "mountpoints": []},
    ],
    "rpi_clone": True,
    "clone_state": {
        "running": False,
        "rc": 0,
        "started": _iso(REF_DT - timedelta(days=2)),
        "lines": [
            "Booting clone source from /dev/nvme0n1 …",
            "Cloning to /dev/sda — partition table copied.",
            "rsync: 142 GB transferred, 0 errors.",
            "Done — bootable USB ready.",
        ],
    },
    "archive_state": {
        "running": False,
        "rc": 0,
        "started": _iso(REF_DT - timedelta(days=3)),
        "lines": [
            "Stopping ClickHouse for archive …",
            "Creating tarball of rootfs + ClickHouse data …",
            "Compressing — this takes a few minutes …",
            "Archive written: archive-" + _date(REF_DT - timedelta(days=3)) +
            ".tar.gz (19.4 GB)",
            "ClickHouse restarted, services healthy.",
        ],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM_TIMESERIES (consumed by /api/system)
# ─────────────────────────────────────────────────────────────────────────────

def _build_system_timeseries():
    """24 hours of points, 1-minute cadence."""
    points = []
    start = REF_DT - timedelta(hours=24)
    for i in range(24 * 60):
        t = start + timedelta(minutes=i)
        hour = t.hour
        base_temp = 52.0
        if hour in (3, 4):
            base_temp = 56.0
        if hour in (14, 15, 16):
            base_temp = 58.0
        temp = round(base_temp + 3.0 * (((i % 30) - 15) / 15.0), 1)
        cpu = 15 + (i % 60) // 10 * 3
        if hour == 3 and (i % 60) < 10:
            cpu = 78
        rpi_fan = temp > 58
        pironman_fan = temp > 60 or (hour == 3 and (i % 60) < 10)
        points.append({
            "time": t.strftime("%Y-%m-%dT%H:%M:%S"),
            "temp_c": temp,
            "cpu_pct": cpu,
            "rpi_fan": rpi_fan,
            "pironman_fan": pironman_fan,
        })
    return points


SYSTEM_TIMESERIES = _build_system_timeseries()


# ─────────────────────────────────────────────────────────────────────────────
# BANDWIDTH (consumed by /api/bandwidth + /api/bandwidth/device-destinations)
# ─────────────────────────────────────────────────────────────────────────────

def _build_bandwidth():
    """Hourly timeseries for today, keyed by per-device IP."""
    talker_ips = [
        ("192.168.50.10", "Laptop A"),
        ("192.168.50.100", "NAS"),
        ("192.168.50.80", "Phone-A"),
        ("192.168.50.20", "Workstation B"),
        ("192.168.50.50", "IoT-Camera-1"),
    ]
    timeseries = []
    totals = {ip: 0 for ip, _ in talker_ips}
    start = REF_DT.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    for i in range(24):
        t = start + timedelta(hours=i)
        rec = {"time": t.strftime("%Y-%m-%dT%H:%M:%S")}
        for j, (ip, _) in enumerate(talker_ips):
            base = [12_000_000, 8_000_000, 4_000_000, 6_000_000, 1_500_000][j]
            mult = 0.4 + 0.6 * max(0, 1 - abs(t.hour - 14) / 12.0)
            val = int(base * mult * (0.7 + 0.3 * ((i + j) % 5) / 5.0))
            rec[ip] = val
            totals[ip] += val
        timeseries.append(rec)

    grand_total = sum(totals.values())

    talkers = []
    for ip, label in talker_ips:
        up = int(totals[ip] * 0.35)
        down = totals[ip] - up
        talkers.append({
            "ip": ip,
            "label": f"{ip} ({label})",
            "up_bytes": up,
            "down_bytes": down,
            "total_bytes": totals[ip],
            "flows": 800 + (totals[ip] // 1_000_000),
            "external_dests": 42,
            "last_active": REF_TS - 60,
        })
    talkers.sort(key=lambda t: -t["total_bytes"])

    peak_idx = max(range(24), key=lambda i: sum(
        timeseries[i][ip] for ip, _ in talker_ips))
    peak_hour_bytes = sum(timeseries[peak_idx][ip] for ip, _ in talker_ips)

    destinations = [
        {"ip": "203.0.113.10", "org": "Cloudflare, Inc.",
         "city": "London", "country": "UK",
         "total_bytes": int(grand_total * 0.32),
         "flows": 1842, "distinct_sources": 5},
        {"ip": "8.8.8.8", "org": "Google LLC",
         "city": "Mountain View", "country": "US",
         "total_bytes": int(grand_total * 0.18),
         "flows": 1245, "distinct_sources": 4},
        {"ip": "203.0.113.200", "org": "Example Hosting Ltd",
         "city": "Frankfurt", "country": "DE",
         "total_bytes": int(grand_total * 0.12),
         "flows": 814, "distinct_sources": 2},
        {"ip": "198.51.100.20", "org": "Example Cloud Storage",
         "city": "Dublin", "country": "IE",
         "total_bytes": int(grand_total * 0.09),
         "flows": 312, "distinct_sources": 1},
        {"ip": "1.1.1.1", "org": "Cloudflare, Inc.",
         "city": "Sydney", "country": "AU",
         "total_bytes": int(grand_total * 0.05),
         "flows": 178, "distinct_sources": 3},
    ]

    series_order = [t["ip"] for t in talkers[:5]]
    series_labels = {t["ip"]: t["label"] for t in talkers}

    return {
        "summary": {
            "total_bytes": grand_total,
            "up_bytes": int(grand_total * 0.32),
            "down_bytes": int(grand_total * 0.68),
            "peak_hour": timeseries[peak_idx]["time"],
            "peak_hour_bytes": peak_hour_bytes,
            "top_device_label": talkers[0]["label"],
            "top_device_bytes": talkers[0]["total_bytes"],
            "device_count": len(talkers),
            "window_days": 1,
        },
        "timeseries": timeseries,
        "series_order": series_order,
        "series_labels": series_labels,
        "talkers": talkers,
        "destinations": destinations,
    }


BANDWIDTH_DATA = _build_bandwidth()

BANDWIDTH_DRILLDOWN = [
    {"ip": "203.0.113.10", "org": "Cloudflare, Inc.",
     "city": "London", "country": "UK",
     "up_bytes": 12_400_000, "down_bytes": 84_300_000, "flows": 612},
    {"ip": "8.8.8.8", "org": "Google LLC",
     "city": "Mountain View", "country": "US",
     "up_bytes": 4_100_000, "down_bytes": 28_700_000, "flows": 412},
    {"ip": "203.0.113.99", "org": "ExampleHost LLC",
     "city": "—", "country": "—",
     "up_bytes": 1_800_000, "down_bytes": 5_200_000, "flows": 288},
]
