"""
hex_dump.py — Generate hex + ASCII dump of raw packet bytes.

This replicates the classic hex dump format you see in Wireshark's
"raw bytes" view. Each line shows:
  - Byte offset (in hex)
  - 16 bytes in hex, grouped in pairs
  - ASCII representation (printable chars, '.' for non-printable)

DCCN concept: This directly shows how protocol headers are stored
as sequences of bytes in memory/on the wire. You can point to specific
byte positions and say "bytes 0-13 are the Ethernet header" etc.
"""


def generate_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Generate a hex + ASCII dump string from raw bytes.

    Args:
        data: Raw packet bytes.
        bytes_per_line: How many bytes per line (default 16, standard).

    Returns:
        Multi-line string with offset, hex, and ASCII columns.

    Example output:
        0000  45 00 00 3c 1c 46 40 00  40 06 b1 e6 ac 10 0a 63  E..<.F@. @......c
        0010  ac 10 0a 0c 00 50 e6 24  00 00 00 00 a0 02 fa f0  .....P.$ ........
    """
    if not data:
        return "(empty packet)"

    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]

        # Offset column: 4 hex digits
        offset_str = f"{offset:04X}"

        # Hex column: each byte as 2 hex digits, space-separated
        # with an extra space in the middle for readability
        hex_parts = []
        for i, byte in enumerate(chunk):
            hex_parts.append(f"{byte:02X}")
            if i == (bytes_per_line // 2 - 1):
                hex_parts.append("")  # extra gap in middle
        hex_str = " ".join(hex_parts)

        # Pad hex column to fixed width for alignment
        # Each byte = 3 chars ("XX "), plus 1 extra space in middle
        expected_width = bytes_per_line * 3 + 1
        hex_str = hex_str.ljust(expected_width)

        # ASCII column: printable chars or '.'
        ascii_str = ""
        for byte in chunk:
            if 32 <= byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str += "."

        lines.append(f"  {offset_str}  {hex_str} {ascii_str}")

    return "\n".join(lines)


def get_raw_bytes(packet) -> bytes:
    """
    Extract raw bytes from a Scapy packet.

    Args:
        packet: A Scapy packet object.

    Returns:
        Raw bytes of the packet.
    """
    try:
        return bytes(packet)
    except Exception:
        return b""
