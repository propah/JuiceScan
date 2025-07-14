"""Core scanning utilities for JuiceScan."""

import logging
from concurrent.futures import ThreadPoolExecutor
from socket import AF_INET, SOCK_STREAM, socket
from typing import cast

import requests
from alive_progress import alive_bar
from scapy.all import IP, TCP, RandShort, sr, sr1  # type: ignore
from scapy.packet import Packet
from termcolor import colored, cprint

from juicescan.parser import CommandInfo, PortType, ScanType

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class ManualPortAnalyzer:
    def __init__(self, command_info: CommandInfo) -> None:
        self.command_info = command_info
        self.open_ports: dict[int, str] = {}

    def scan(self) -> None:
        logging.disable(logging.CRITICAL)
        cprint(
            f"🔎 Scanning {self.command_info.ipv4}...",
            "white",
            "on_cyan",
            attrs=["bold"],
        )

        match self.command_info.scan_type:
            case ScanType.OPEN:
                self.open_port_scan()
            case ScanType.SYN:
                self.syn_port_scan()

        cprint("Juiced ports:", "cyan", "on_white", attrs=["dark"])
        for open_port, banner in self.open_ports.items():
            if banner == "":
                cprint(f"📦 {open_port} ", "white", "on_green")
            else:
                cprint(f"📦 {open_port} : {banner} ", "white", "on_green")

    def open_port_scan(self) -> None:
        total, iterations = self._iter_ports()
        with alive_bar(
            total,
            enrich_print=False,
            dual_line=True,
        ) as bar:
            bar.text = colored("😖 Juiced 0 port 😖")
            with ThreadPoolExecutor(max_workers=self.command_info.threads) as executor:
                for port in iterations:
                    executor.submit(self._scan_port_open, port, bar)

    def _scan_port_open(self, port: int, bar) -> None:
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.command_info.ipv4, port))
            self.open_ports.update({port: ""})
            bar.text = colored(f"💦 Juiced {len(self.open_ports)} ports 💦")
            banner = sock.recv(512)
            self.open_ports.update({port: str(banner)})
            sock.close()
        except Exception:
            pass
        bar()

    def syn_port_scan(self) -> None:
        total, iterations = self._iter_ports()
        with alive_bar(total, enrich_print=False, dual_line=True) as bar:
            bar.text = colored("😖 Juiced 0 port 😖")
            with ThreadPoolExecutor(max_workers=self.command_info.threads) as executor:
                for port in iterations:
                    executor.submit(self._scan_port_syn, port, bar)
        try:
            if self.open_ports:
                sr(
                    IP(dst=self.command_info.ipv4)
                    / TCP(dport=list(self.open_ports.keys()), flags="R"),
                    timeout=1,
                )
        except Exception:
            pass

    def _scan_port_syn(self, port: int, bar) -> None:
        sport = RandShort()
        try:
            answer = cast(
                Packet | None,
                sr1(
                    IP(dst=self.command_info.ipv4)
                    / TCP(sport=sport, dport=port, flags="S"),
                    timeout=1,
                    verbose=False,
                ),
            )
            if isinstance(answer, Packet) and answer.haslayer(TCP):
                tcp_layer = cast(TCP, answer.getlayer(TCP))
                if tcp_layer.flags & 0x12:
                    self.open_ports[port] = ""
                    sr1(
                        IP(dst=self.command_info.ipv4)
                        / TCP(sport=sport, dport=port, flags="R"),
                        timeout=1,
                        verbose=False,
                    )
            bar.text = colored(f"💦 Juiced {len(self.open_ports)} ports 💦")
        except Exception:
            pass
        bar()

    def _iter_ports(self) -> tuple[int, list[int] | range]:
        if self.command_info.port_type == PortType.LIST:
            return len(self.command_info.ports), self.command_info.ports
        start, end = self.command_info.ports
        return end - start, range(start, end)


class ShodanPortAnalyzer:
    def __init__(self, command_info: CommandInfo):
        self.command_info = command_info

    def scan(self):
        url = "https://internetdb.shodan.io/" + self.command_info.ipv4
        resp = requests.get(url)
        json = resp.json()
        cprint("Shodan juiced ports:", "cyan", "on_white", attrs=["dark"])
        for open_port in json.get("ports"):
            cprint(f"📦 {open_port}", "white", "on_green")
