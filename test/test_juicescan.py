from juicescan.parser import CommandInfo, PortType, ScanType, is_valid_ip_address


def test_is_valid_ip_address_ok() -> None:
    assert is_valid_ip_address("192.168.0.1")


def test_is_valid_ip_address_ko() -> None:
    assert not is_valid_ip_address("abc123.4.5.6.7")


def test_command_info_from_port_list() -> None:
    info = CommandInfo.from_port_list("1.1.1.1", threads=1, ports=[80, 443])
    assert info.port_type is PortType.LIST
    assert info.ports == [80, 443]
    assert info.scan_type is ScanType.OPEN


def test_command_info_from_port_range() -> None:
    info = CommandInfo.from_port_range("1.1.1.1", threads=1, port_min=10, port_max=20)
    assert info.port_type is PortType.RANGE
    assert info.ports == [10, 20]
