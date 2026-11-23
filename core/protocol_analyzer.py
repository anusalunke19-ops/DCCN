"""
protocol_analyzer.py — Aggregate statistics and behavior analytics from packet data.

Analyzes collections of parsed packets to calculate:
- Protocol distribution
- Top communicating IP addresses (talkers/listeners)
- Port activity (services accessed)
- TCP flag distributions
- Traffic volume and packet rates over time
- DNS query analytics
"""

import pandas as pd
from typing import Dict, Any, List


def analyze_protocols(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Compute protocol breakdown metrics.
    """
    if df.empty or "protocol" not in df.columns:
        return {"counts": {}, "percentages": {}}

    counts = df["protocol"].value_counts().to_dict()
    total = len(df)
    percentages = {k: round((v / total) * 100, 2) for k, v in counts.items()}

    return {
        "counts": counts,
        "percentages": percentages,
        "total_packets": total,
    }


def analyze_top_ips(df: pd.DataFrame, top_n: int = 10) -> Dict[str, Any]:
    """
    Identify top talkers (source IPs) and top listeners (destination IPs).
    """
    if df.empty:
        return {"top_src": {}, "top_dst": {}, "top_endpoints": {}}

    src_counts = df["src_ip"].dropna().value_counts().head(top_n).to_dict()
    dst_counts = df["dst_ip"].dropna().value_counts().head(top_n).to_dict()

    # Combined all endpoints
    all_ips = pd.concat([df["src_ip"].dropna(), df["dst_ip"].dropna()]).value_counts().head(top_n).to_dict()

    return {
        "top_src": src_counts,
        "top_dst": dst_counts,
        "top_endpoints": all_ips,
    }


def analyze_top_ports(df: pd.DataFrame, top_n: int = 10) -> Dict[str, Any]:
    """
    Calculate most active service ports.
    """
    if df.empty:
        return {"ports": {}}

    ports_series = pd.concat([
        df["src_port"].dropna(),
        df["dst_port"].dropna()
    ])

    def _clean_port(val):
        try:
            return str(int(float(val)))
        except (ValueError, TypeError):
            return str(val)

    ports = ports_series.apply(_clean_port).value_counts().head(top_n).to_dict()

    return {"ports": ports}


def analyze_tcp_flags(df: pd.DataFrame) -> Dict[str, int]:
    """
    Calculate breakdown of individual TCP flags observed across packets.
    """
    if df.empty or "tcp_flags" not in df.columns:
        return {}

    flags_counts = {
        "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0
    }

    tcp_df = df[df["tcp_flags"].notna() & (df["tcp_flags"] != "—") & (df["tcp_flags"] != "")]
    for flags_val in tcp_df["tcp_flags"].astype(str):
        if "S" in flags_val: flags_counts["SYN"] += 1
        if "A" in flags_val: flags_counts["ACK"] += 1
        if "F" in flags_val: flags_counts["FIN"] += 1
        if "R" in flags_val: flags_counts["RST"] += 1
        if "P" in flags_val: flags_counts["PSH"] += 1
        if "U" in flags_val: flags_counts["URG"] += 1

    return {k: v for k, v in flags_counts.items() if v > 0}


def analyze_dns_queries(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Aggregate DNS resolution statistics.
    """
    if df.empty or "dns_qname" not in df.columns:
        return {"domains": {}, "query_types": {}, "total_queries": 0}

    dns_df = df[df["dns_qname"].notna() & (df["dns_qname"] != "—")]
    if dns_df.empty:
        return {"domains": {}, "query_types": {}, "total_queries": 0}

    domain_counts = dns_df["dns_qname"].value_counts().head(10).to_dict()
    qtype_counts = dns_df["dns_qtype_str"].value_counts().to_dict() if "dns_qtype_str" in dns_df.columns else {}

    return {
        "domains": domain_counts,
        "query_types": qtype_counts,
        "total_queries": len(dns_df),
    }


def analyze_traffic_timeline(df: pd.DataFrame, bins: int = 25) -> pd.DataFrame:
    """
    Bucket packets into time intervals for volume and rate charts.
    """
    if df.empty or "timestamp" not in df.columns or df["timestamp"].dropna().empty:
        return pd.DataFrame()

    valid_ts = df["timestamp"].dropna()
    min_t, max_t = valid_ts.min(), valid_ts.max()
    if min_t == max_t:
        return pd.DataFrame([{"time_bin": 0.0, "packet_count": len(df), "byte_volume": df["length"].sum()}])

    df_copy = df[df["timestamp"].notna()].copy()
    df_copy["time_rel"] = df_copy["timestamp"] - min_t

    df_copy["bin"] = pd.cut(df_copy["time_rel"], bins=bins)
    grouped = df_copy.groupby("bin", observed=False).agg(
        packet_count=("num", "count"),
        byte_volume=("length", "sum")
    ).reset_index()

    grouped["bin_mid"] = grouped["bin"].apply(lambda b: round(b.mid, 3) if hasattr(b, 'mid') else 0)
    return grouped
