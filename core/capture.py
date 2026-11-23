"""
capture.py — Live packet capture engine with threaded sniffing and bounded queue.

Architecture:
- Runs Scapy's sniff() in a separate daemon thread to prevent blocking the UI.
- Pushes incoming packets into a bounded queue (queue.Queue(maxsize=MAX_CAPTURE_PACKETS)).
- Checks a threading.Event flag for graceful, responsive stopping.
- Automatically handles Windows interface resolution (friendly names vs GUIDs).
- Gracefully reports errors (Npcap missing, permissions, invalid interface).
"""

from __future__ import annotations

import sys
import threading
import queue
import logging
from typing import List, Dict, Any, Optional, Tuple

from scapy.all import sniff, Packet, conf
from config.settings import (
    MAX_CAPTURE_PACKETS, DEFAULT_CAPTURE_LIMIT, SNIFF_TIMEOUT
)
from core.packet_parser import parse_packet

logger = logging.getLogger(__name__)


def is_live_capture_available() -> Tuple[bool, str]:
    """
    Check if the current host environment supports live packet capture.

    Returns:
        (available, message)
    """
    if sys.platform == "win32":
        if not getattr(conf, "use_pcap", False):
            return False, (
                "Npcap driver not detected. Live capture on Windows requires Npcap. "
                "You can still load and analyze offline PCAP files without Npcap. "
                "To enable live capture, install Npcap from https://npcap.com in 'WinPcap API-compatible mode'."
            )
    return True, "Live capture provider available."


def get_available_interfaces() -> List[Dict[str, str]]:
    """
    Enumerate network interfaces with human-friendly descriptions.

    Returns:
        List of dicts: [{'id': str, 'name': str, 'description': str}]
    """
    interfaces = []
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
            for iface in win_ifaces:
                name = iface.get("name", "Unknown")
                desc = iface.get("description", "")
                guid = iface.get("guid", name)
                # Prioritize active adapters like Wi-Fi and Ethernet
                interfaces.append({
                    "id": name,
                    "name": name,
                    "description": f"{name} ({desc})" if desc else name,
                    "guid": guid
                })
        except Exception as e:
            logger.warning(f"Failed to get Windows interface list: {e}")

    # Fallback / cross-platform
    if not interfaces:
        for iface in conf.ifaces.values():
            interfaces.append({
                "id": str(iface.name),
                "name": str(iface.name),
                "description": str(iface.description or iface.name),
                "guid": str(iface.name)
            })

    return interfaces


class LiveCaptureEngine:
    """
    Thread-safe controller for live packet sniffing sessions.
    """

    def __init__(self, max_buffer: int = MAX_CAPTURE_PACKETS):
        self.max_buffer = max_buffer
        self.packet_queue: queue.Queue = queue.Queue(maxsize=max_buffer)
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.is_capturing: bool = False
        self.error_message: Optional[str] = None
        self.packet_limit: int = DEFAULT_CAPTURE_LIMIT
        self.packets_captured_count: int = 0
        self.lock = threading.Lock()

    def start(self, interface: str, packet_limit: int = DEFAULT_CAPTURE_LIMIT, bpf_filter: str = "") -> Tuple[bool, Optional[str]]:
        """
        Start capturing on the specified interface.
        """
        with self.lock:
            if self.is_capturing:
                return False, "Capture is already active."

            avail, msg = is_live_capture_available()
            if not avail:
                return False, msg

            self.stop_event.clear()
            self.error_message = None
            self.packet_limit = packet_limit
            self.packets_captured_count = 0

            # Drain any residual packets from previous session
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break

            self.thread = threading.Thread(
                target=self._capture_worker,
                args=(interface, bpf_filter),
                daemon=True,
                name="LiveCaptureWorker"
            )
            self.is_capturing = True
            self.thread.start()
            return True, None

    def stop(self, timeout: float = 2.5) -> None:
        """
        Stop the active capture cleanly and ensure worker thread exits.
        """
        with self.lock:
            if not self.is_capturing and (self.thread is None or not self.thread.is_alive()):
                return
            self.stop_event.set()
            if self.thread and self.thread.is_alive() and threading.current_thread() != self.thread:
                self.thread.join(timeout=timeout)
            self.is_capturing = False

    def _capture_worker(self, interface: str, bpf_filter: str) -> None:
        """
        Background worker that runs sniff() with periodic stop-checks.
        """
        def _packet_callback(pkt: Packet):
            if self.stop_event.is_set():
                return

            try:
                self.packet_queue.put_nowait(pkt)
                self.packets_captured_count += 1
            except queue.Full:
                pass  # Drop packet if buffer is full to prevent memory exhaustion

            if self.packets_captured_count >= self.packet_limit:
                self.stop_event.set()

        try:
            sniff_kwargs: Dict[str, Any] = {
                "prn": _packet_callback,
                "stop_filter": lambda _: self.stop_event.is_set(),
                "store": False,
                "timeout": SNIFF_TIMEOUT,
            }
            if interface:
                sniff_kwargs["iface"] = interface
            if bpf_filter:
                sniff_kwargs["filter"] = bpf_filter

            while not self.stop_event.is_set():
                sniff(**sniff_kwargs)
                if self.packets_captured_count >= self.packet_limit:
                    break

        except Exception as e:
            logger.error(f"Error in capture worker: {e}")
            self.error_message = str(e)
        finally:
            self.is_capturing = False
            self.stop_event.set()

    def get_new_packets(self) -> List[Packet]:
        """
        Drain all pending packets from the queue and return them.
        Non-blocking.
        """
        drained: List[Packet] = []
        while not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get_nowait()
                drained.append(pkt)
            except queue.Empty:
                break
        return drained
