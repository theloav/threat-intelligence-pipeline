"""Tests for IOCNormaliser."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tip.core.models import IOC, IOCType, ThreatLevel
from tip.misp.normaliser import IOCNormaliser


def _now():
    """Naive-UTC now for test fixtures."""
    return datetime.now(UTC).replace(tzinfo=None)


def _ioc(value: str, ioc_type: IOCType) -> IOC:
    return IOC(
        value=value,
        ioc_type=ioc_type,
        source_feed="test",
        threat_level=ThreatLevel.MEDIUM,
        first_seen=_now(),
        last_seen=_now(),
    )


@pytest.fixture
def norm():
    return IOCNormaliser()


def test_private_ip_is_skipped(norm):
    assert norm.normalise(_ioc("192.168.1.1", IOCType.IP)) is None


def test_loopback_is_skipped(norm):
    assert norm.normalise(_ioc("127.0.0.1", IOCType.IP)) is None


def test_valid_public_ip_passes(norm):
    result = norm.normalise(_ioc("8.8.8.8", IOCType.IP))
    assert result is not None
    assert result.value == "8.8.8.8"


def test_link_local_is_skipped(norm):
    assert norm.normalise(_ioc("169.254.1.1", IOCType.IP)) is None


def test_multicast_is_skipped(norm):
    assert norm.normalise(_ioc("224.0.0.1", IOCType.IP)) is None


def test_hash_wrong_length_is_skipped(norm):
    """31-char 'md5' is invalid → None."""
    result = norm.normalise(_ioc("a" * 31, IOCType.MD5))
    assert result is None


def test_md5_correct_length_passes(norm):
    result = norm.normalise(_ioc("d" * 32, IOCType.MD5))
    assert result is not None


def test_sha256_correct_length_passes(norm):
    result = norm.normalise(_ioc("e" * 64, IOCType.SHA256))
    assert result is not None


def test_sha1_wrong_length_is_skipped(norm):
    result = norm.normalise(_ioc("f" * 39, IOCType.SHA1))
    assert result is None


def test_hash_non_hex_chars_skipped(norm):
    result = norm.normalise(_ioc("z" * 32, IOCType.MD5))
    assert result is None


def test_hash_lowercased(norm):
    result = norm.normalise(_ioc("A" * 64, IOCType.SHA256))
    assert result is not None
    assert result.value == "a" * 64


def test_empty_md5_hash_skipped(norm):
    """MD5 of empty file is filtered."""
    result = norm.normalise(_ioc("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5))
    assert result is None


def test_domain_lowercased(norm):
    result = norm.normalise(_ioc("EVIL.COM", IOCType.DOMAIN))
    assert result is not None
    assert result.value == "evil.com"


def test_domain_www_stripped(norm):
    result = norm.normalise(_ioc("www.evil.com", IOCType.DOMAIN))
    assert result is not None
    assert result.value == "evil.com"


def test_domain_no_dot_skipped(norm):
    result = norm.normalise(_ioc("localhost", IOCType.DOMAIN))
    assert result is None


def test_internal_domain_skipped(norm):
    result = norm.normalise(_ioc("server.local", IOCType.DOMAIN))
    assert result is None


def test_url_must_start_with_http(norm):
    result = norm.normalise(_ioc("ftp://evil.com/bad", IOCType.URL))
    assert result is None


def test_url_https_passes(norm):
    result = norm.normalise(_ioc("https://evil.com/bad", IOCType.URL))
    assert result is not None


def test_url_http_passes(norm):
    result = norm.normalise(_ioc("http://evil.com/payload.exe", IOCType.URL))
    assert result is not None


def test_email_valid(norm):
    result = norm.normalise(_ioc("bad@evil.com", IOCType.EMAIL))
    assert result is not None
    assert result.value == "bad@evil.com"


def test_email_no_at_skipped(norm):
    result = norm.normalise(_ioc("notanemail", IOCType.EMAIL))
    assert result is None


def test_normalise_batch_deduplicates(norm):
    iocs = [
        _ioc("8.8.8.8", IOCType.IP),
        _ioc("8.8.8.8", IOCType.IP),  # duplicate
        _ioc("192.168.1.1", IOCType.IP),  # private — filtered
        _ioc("evil.com", IOCType.DOMAIN),
    ]
    result = norm.normalise_batch(iocs)
    values = [i.value for i in result]
    assert values.count("8.8.8.8") == 1  # deduplicated
    assert "192.168.1.1" not in values  # filtered
    assert "evil.com" in values


def test_extract_domain_from_url(norm):
    domain = norm.extract_domain_from_url("http://evil.com/path")
    assert domain == "evil.com"


def test_extract_domain_returns_none_for_invalid(norm):
    result = norm.extract_domain_from_url("not-a-url")
    assert result is None
