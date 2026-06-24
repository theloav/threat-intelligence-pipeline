from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlparse

from tip.core.models import IOC, IOCType

logger = logging.getLogger(__name__)

HASH_LENGTHS = {
    IOCType.MD5: 32,
    IOCType.SHA1: 40,
    IOCType.SHA256: 64,
}

INTERNAL_DOMAINS = frozenset(
    {
        "localhost",
        "local",
        "internal",
        "corp",
        "lan",
        "home",
        "example.com",
        "example.org",
        "example.net",
        "test",
        "invalid",
    }
)


class IOCNormaliser:
    def normalise(self, ioc: IOC) -> IOC | None:
        """Clean and validate IOC. Return None to skip."""
        value = ioc.value.strip()
        if not value:
            return None

        try:
            if ioc.ioc_type == IOCType.IP:
                return self._normalise_ip(ioc, value)
            elif ioc.ioc_type == IOCType.DOMAIN:
                return self._normalise_domain(ioc, value)
            elif ioc.ioc_type == IOCType.URL:
                return self._normalise_url(ioc, value)
            elif ioc.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
                return self._normalise_hash(ioc, value)
            elif ioc.ioc_type == IOCType.EMAIL:
                return self._normalise_email(ioc, value)
            elif ioc.ioc_type == IOCType.FILENAME:
                return self._normalise_filename(ioc, value)
        except Exception as exc:
            logger.debug("Normalisation error for %s: %s", value, exc)
        return None

    def _normalise_ip(self, ioc: IOC, value: str) -> IOC | None:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return None
        if self.is_private_ip(value):
            return None
        return ioc.model_copy(update={"value": str(addr)})

    def _normalise_domain(self, ioc: IOC, value: str) -> IOC | None:
        domain = value.lower().strip(".")
        if domain.startswith("www."):
            domain = domain[4:]
        if "." not in domain:
            return None
        tld = domain.rsplit(".", 1)[-1]
        if tld in INTERNAL_DOMAINS or domain in INTERNAL_DOMAINS:
            return None
        if len(domain) < 4 or len(domain) > 253:
            return None
        return ioc.model_copy(update={"value": domain})

    def _normalise_url(self, ioc: IOC, value: str) -> IOC | None:
        if not value.startswith(("http://", "https://")):
            return None
        try:
            parsed = urlparse(value)
            if not parsed.netloc:
                return None
        except Exception:
            return None
        return ioc.model_copy(update={"value": value})

    def _normalise_hash(self, ioc: IOC, value: str) -> IOC | None:
        cleaned = value.lower().strip()
        expected_len = HASH_LENGTHS.get(ioc.ioc_type)
        if expected_len and len(cleaned) != expected_len:
            return None
        if not re.match(r"^[0-9a-f]+$", cleaned):
            return None
        # Skip obviously null hashes
        if cleaned in {
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty
        }:
            return None
        return ioc.model_copy(update={"value": cleaned})

    def _normalise_email(self, ioc: IOC, value: str) -> IOC | None:
        if "@" not in value or len(value) < 6:
            return None
        return ioc.model_copy(update={"value": value.lower()})

    def _normalise_filename(self, ioc: IOC, value: str) -> IOC | None:
        if not value or len(value) < 2:
            return None
        return ioc

    def is_private_ip(self, value: str) -> bool:
        """True for RFC1918, loopback, link-local, multicast, reserved."""
        try:
            addr = ipaddress.ip_address(value)
            return (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
                or addr.is_unspecified
            )
        except ValueError:
            return False

    def extract_domain_from_url(self, url: str) -> str | None:
        """Parse domain from URL."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host and "." in host:
                return host.lower()
        except Exception:
            pass
        return None

    def normalise_batch(self, iocs: list[IOC]) -> list[IOC]:
        """Normalise list, filtering None results. Deduplicates by (value, type)."""
        seen: set[tuple[str, str]] = set()
        result: list[IOC] = []
        for ioc in iocs:
            normalised = self.normalise(ioc)
            if normalised is None:
                continue
            key = (normalised.value, normalised.ioc_type.value)
            if key in seen:
                continue
            seen.add(key)
            result.append(normalised)
        return result
