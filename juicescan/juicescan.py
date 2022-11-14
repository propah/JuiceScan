import logging
from concurrent.futures import ThreadPoolExecutor
from socket import AF_INET, SOCK_STREAM, socket

import requests
from alive_progress import alive_bar
from scapy.all import IP, TCP, RandShort, sr, sr1  # type: ignore
from termcolor import colored, cprint

from juicescan.parser import CommandInfo, PortType, ScanType

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class ManualPortAnalyzer:
    def __init__(self, command_info: CommandInfo) -> None:
        self.command_info = command_info
        self.open_ports: dict[int, str] = {}

    def scan(self):
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

    def open_port_scan(self):
        total: int
        iterations: list[int] | range
        match self.command_info.port_type:
            case PortType.LIST:
                total = len(self.command_info.ports)
                iterations = self.command_info.ports
            case PortType.RANGE:
                total = self.command_info.ports[1] - self.command_info.ports[0]
                iterations = range(
                    self.command_info.ports[0], self.command_info.ports[1]
                )
        with alive_bar(
            total,
            enrich_print=False,
            dual_line=True,
        ) as bar:
            bar.text = colored("😖 Juiced 0 port 😖")
            with ThreadPoolExecutor(max_workers=self.command_info.threads) as executor:
                for port in iterations:
                    executor.submit(self._scan_port_open, port, bar)

    def _scan_port_open(self, port: int, bar):
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

    def syn_port_scan(self):
        try:
            match self.command_info.port_type:
                case PortType.RANGE:
                    total: int
                    iterations: list[int] | range
                    match self.command_info.port_type:
                        case PortType.LIST:
                            total = len(self.command_info.ports)
                            iterations = self.command_info.ports
                        case PortType.RANGE:
                            total = (
                                self.command_info.ports[1] - self.command_info.ports[0]
                            )
                            iterations = range(
                                self.command_info.ports[0], self.command_info.ports[1]
                            )
                    with alive_bar(
                        total,
                        enrich_print=False,
                        dual_line=True,
                    ) as bar:
                        bar.text = colored("😖 Juiced 0 port 😖")
                        with ThreadPoolExecutor(
                            max_workers=self.command_info.threads
                        ) as executor:
                            for port in range(
                                self.command_info.ports[0], self.command_info.ports[1]
                            ):
                                executor.submit(self._scan_port_syn, port, bar)
                case PortType.LIST:
                    answers, _unans = sr(
                        IP(dst=self.command_info.ipv4)
                        / TCP(
                            sport=RandShort(), dport=self.command_info.ports, flags="S"
                        ),
                        timeout=1,
                        verbose=True,
                    )
            # Reset connections
            sr(
                IP(dst=self.command_info.ipv4)
                / TCP(dport=self.open_ports.keys(), flags="AR"),
                timeout=1,
            )
        except Exception as e:
            print(e)
            pass

    def _scan_port_syn(self, port: int, bar):
        sport = RandShort()
        try:
            answer = sr1(
                IP(dst=self.command_info.ipv4)
                / TCP(sport=sport, dport=port, flags="S"),
                timeout=1,
                verbose=False,
            )
            if answer[TCP].flags != "RA":
                self.open_ports.update({port: ""})
            bar.text = colored(f"💦 Juiced {len(self.open_ports)} ports 💦")
        except Exception:
            pass
        bar()


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
