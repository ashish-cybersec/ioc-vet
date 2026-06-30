from iocvet.core.detector import detect_ioc_type, normalize
from iocvet.core.models import IOCType


def test_ipv4():
    assert detect_ioc_type("8.8.8.8") == IOCType.IPV4


def test_ipv6():
    assert detect_ioc_type("2001:4860:4860::8888") == IOCType.IPV6


def test_domain():
    assert detect_ioc_type("example.com") == IOCType.DOMAIN
    assert detect_ioc_type("sub.example.co.uk") == IOCType.DOMAIN


def test_url():
    assert detect_ioc_type("https://example.com/payload.exe") == IOCType.URL
    assert detect_ioc_type("http://evil.tld/bad") == IOCType.URL


def test_md5():
    assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == IOCType.MD5


def test_sha1():
    assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.SHA1


def test_sha256():
    assert (
        detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        == IOCType.SHA256
    )


def test_unknown_for_garbage():
    assert detect_ioc_type("not a valid ioc!!") == IOCType.UNKNOWN


def test_unknown_for_empty():
    assert detect_ioc_type("") == IOCType.UNKNOWN
    assert detect_ioc_type("   ") == IOCType.UNKNOWN


def test_normalize_lowercases_hashes_and_domains():
    assert normalize("ABCDEF", IOCType.DOMAIN) == "abcdef"
    assert normalize("DEADBEEF", IOCType.MD5) == "deadbeef"


def test_normalize_preserves_ip_case_na():
    # IPs have no case to normalize; just confirm passthrough.
    assert normalize("8.8.8.8", IOCType.IPV4) == "8.8.8.8"
