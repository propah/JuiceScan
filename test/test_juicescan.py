from juicescan.parser import is_valid_ip_address


def test_is_valid_ip_address_ok() -> None:
    assert is_valid_ip_address("192.168.0.1")


def test_is_valid_ip_address_ko() -> None:
    assert not is_valid_ip_address("abc123.4.5.6.7")
