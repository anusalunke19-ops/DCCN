"""
helpers.py — Utility functions used across the application.

These are small, pure functions for formatting, conversion, and safe
data handling. They have no side effects and are easy to test.
"""

from datetime import datetime, timezone


def format_timestamp(epoch_time: float) -> str:
    """
    Convert a Unix epoch timestamp (float) to a human-readable string.

    Scapy stores packet timestamps as floats (seconds since 1970-01-01).
    We convert to local time for display.

    Args:
        epoch_time: Seconds since Unix epoch (e.g. 1700000000.123456).

    Returns:
        Formatted string like "2024-01-15 14:30:22.123456".
    """
    try:
        dt = datetime.fromtimestamp(epoch_time)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    except (OSError, ValueError, OverflowError):
        return "N/A"


def format_timestamp_short(epoch_time: float) -> str:
    """Short timestamp for tables: HH:MM:SS.mmm"""
    try:
        dt = datetime.fromtimestamp(epoch_time)
        return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
    except (OSError, ValueError, OverflowError):
        return "N/A"


def format_bytes(num_bytes: int) -> str:
    """
    Convert a byte count to a human-readable string.

    Examples:
        format_bytes(1024) -> "1.00 KB"
        format_bytes(1048576) -> "1.00 MB"
        format_bytes(500) -> "500 B"
    """
    if num_bytes < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}" if unit != "B" else f"{num_bytes} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} TB"


def format_duration(seconds: float) -> str:
    """
    Convert a duration in seconds to a readable string.

    Examples:
        format_duration(0.5) -> "500.0 ms"
        format_duration(65) -> "1m 5.00s"
        format_duration(3661) -> "1h 1m 1.00s"
    """
    if seconds < 0:
        return "N/A"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes < 60:
        return f"{minutes}m {secs:.2f}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m {secs:.2f}s"


def safe_str(value, default: str = "N/A") -> str:
    """
    Safely convert any value to a string.

    Packet fields can sometimes be None, bytes, or unexpected types.
    This ensures we always get a displayable string.
    """
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def tcp_flags_to_str(flags) -> str:
    """
    Convert Scapy TCP flags to a human-readable string.

    Scapy represents TCP flags as a FlagValue object or string like "SA".
    We convert to something like "SYN, ACK".

    Args:
        flags: Scapy FlagValue or string (e.g. "SA", "S", "FA").

    Returns:
        Human-readable string like "SYN, ACK".
    """
    from config.settings import TCP_FLAGS

    if flags is None:
        return ""
    flag_str = str(flags)
    readable = []
    for char in flag_str:
        if char in TCP_FLAGS:
            readable.append(TCP_FLAGS[char])
        else:
            readable.append(char)
    return ", ".join(readable)


def tcp_flags_to_short(flags) -> str:
    """
    Return the raw short flag string (e.g. "SA", "S", "FA").
    Useful for table columns where space is limited.
    """
    if flags is None:
        return ""
    return str(flags)
