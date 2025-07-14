import argparse
import ipaddress
from dataclasses import dataclass
from enum import Enum

from termcolor import colored, cprint


def is_valid_ip_address(ip_string) -> bool:
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


class ScanType(Enum):
    OPEN = 1
    SYN = 2


class PortType(Enum):
    LIST = 1
    RANGE = 2


@dataclass
class CommandInfo:
    """Container for parsed CLI arguments."""

    ipv4: str
    threads: int
    ports: list[int]
    port_type: PortType
    scan_type: ScanType = ScanType.OPEN

    @classmethod
    def from_port_list(cls, ipv4: str, threads: int, ports: list[int]):
        """Create CommandInfo for a list of ports."""
        return cls(ipv4, threads, ports, PortType.LIST)

    @classmethod
    def from_port_range(
        cls, ipv4: str, threads: int, port_min: int, port_max: int
    ) -> "CommandInfo":
        """Create CommandInfo for a port range."""
        return cls(ipv4, threads, [port_min, port_max], PortType.RANGE)


class Parser:
    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            prog="juicescan",
            usage="%(prog)s ipv4 -p ports -t threads",
            description=colored(
                "🧃 JuiceScan, the juiciest information gathering tool",
                "green",
                attrs=["bold"],
            ),
        )
        self.parser.add_argument(
            "ipv4",
            metavar="ipv4",
            type=str,
            help=colored("🎯 target's ipv4 address (e.g 192.168.0.1)", "grey"),
        )

        self.parser.add_argument(
            "--port",
            "-p",
            type=str,
            action="store",
            help=colored(
                "🎯 target's port(s), if none provided will scan all. Range: -p 30-80 List: -p 80,443 (0 < port < 65535)",
                "grey",
            ),
        )

        self.parser.add_argument(
            "--thread",
            "-t",
            type=int,
            action="store",
            help=colored(
                "🤖 maximum amount of simultaneous connections on the target. Default: 100 (0 < threads < 5000)",
                "grey",
            ),
            default="100",
        )

        self.parser.add_argument(
            "--syn",
            action="store_true",
            help=colored("use TCP SYN scan instead of connect scan", "grey"),
        )

    def validate(self) -> CommandInfo:
        port_min: int = 1
        port_max: int = 65535
        ports: list[int] = []
        self.args: argparse.Namespace = self.parser.parse_args()

        if not is_valid_ip_address(self.args.ipv4):
            cprint("❌ Invalid ip address", "red", "on_yellow")
            exit()
        if self.args.port is not None:
            self.args.port = self.args.port.replace(" ", "")
            if "," in self.args.port:
                ports_str = self.args.port.split(",")
                try:
                    ports = [int(x) for x in ports_str]
                except Exception:
                    cprint("❌ Invalid list of ports", "red", "on_yellow")
                    exit()
            elif "-" in self.args.port:
                ports_str = self.args.port.split("-")
                if ports_str[0] == "" and ports_str[1] == "":
                    ports_str = []
                try:
                    match len(ports_str):
                        case 0:
                            pass
                        case 2:
                            port_min = min(int(ports_str[0]), int(ports_str[1]))
                            if port_min < 1 or port_min > 65535:
                                cprint(
                                    f"❌ Invalid minimum port {port_min}",
                                    "red",
                                    "on_yellow",
                                )
                                exit()
                            port_max = max(int(ports_str[0]), int(ports_str[1]))
                            if port_max < 1 or port_max > 65535:
                                cprint(
                                    f"❌ Invalid maximum port {port_max}",
                                    "red",
                                    "on_yellow",
                                )
                                exit()
                        case _:
                            cprint(
                                "❌ Invalid usage of port range, e.g -p 40-800 or -p-",
                                "red",
                                "on_yellow",
                            )
                            exit()
                except Exception:
                    cprint("❌ Invalid range of ports", "red", "on_yellow")
                    exit()
            else:
                try:
                    port_min = int(self.args.port)
                    port_max = port_min
                except Exception:
                    cprint("❌ Invalid port", "red", "on_yellow")
                    exit()
        if self.args.thread is not None:
            if self.args.thread <= 0 or self.args.thread >= 5000:
                cprint(
                    f"❌ Invalid number of threads (0 < {self.args.thread} < 5000) ",
                    "red",
                    "on_yellow",
                )
                exit()
        if ports != [] or port_min == port_max:
            cmd = CommandInfo.from_port_list(
                ipv4=self.args.ipv4, threads=self.args.thread, ports=ports
            )
        else:
            cmd = CommandInfo.from_port_range(
                ipv4=self.args.ipv4,
                threads=self.args.thread,
                port_min=port_min,
                port_max=port_max,
            )
        if self.args.syn:
            cmd.scan_type = ScanType.SYN
        return cmd
