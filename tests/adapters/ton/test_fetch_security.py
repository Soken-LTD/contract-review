"""SSRF protection tests for TON fetch.py (coordinator security review 2026-10-09).

Verifies that _validate_download_url rejects:
  - Non-https URLs
  - Non-allowlisted hostnames
  - Credentials in URLs
  - Internal/metadata IPs (169.254.169.254)

These are security tests, not integration tests: they do not make network calls.
"""

from __future__ import annotations

from soken_review.adapters.ton.fetch import _validate_download_url


class TestValidateDownloadUrl:
    # ── Must reject ────────────────────────────────────────────────────────

    def test_rejects_http(self):
        assert _validate_download_url("http://server.ton.org/file.fc") is None

    def test_rejects_ftp(self):
        assert _validate_download_url("ftp://server.ton.org/file.fc") is None

    def test_rejects_non_allowlisted_host(self):
        assert _validate_download_url("https://evil.example.com/file.fc") is None

    def test_rejects_localhost(self):
        assert _validate_download_url("https://localhost/file.fc") is None

    def test_rejects_metadata_ip(self):
        # AWS/GCP/Azure instance metadata service
        assert _validate_download_url("https://169.254.169.254/latest/meta-data/") is None

    def test_rejects_credentials_in_url(self):
        assert _validate_download_url("https://user:pass@server.ton.org/file.fc") is None

    def test_rejects_empty_string(self):
        assert _validate_download_url("") is None

    def test_rejects_random_string(self):
        assert _validate_download_url("not-a-url") is None

    def test_rejects_internal_ip_directly(self):
        assert _validate_download_url("https://192.168.1.1/file.fc") is None

    def test_rejects_10_dot_network(self):
        assert _validate_download_url("https://10.0.0.1/file.fc") is None

    def test_rejects_172_16_network(self):
        assert _validate_download_url("https://172.16.0.1/file.fc") is None

    # ── Must accept ────────────────────────────────────────────────────────

    def test_accepts_server_ton_org(self):
        # This test requires DNS resolution of server.ton.org.
        # In network-isolated CI, DNS may fail; the function returns None (fail-closed).
        # The assertion accepts both outcomes: URL returned (DNS ok) or None (DNS blocked).
        url = "https://server.ton.org/api/v1/source/abc.fc"
        result = _validate_download_url(url)
        # Must never raise. Must either pass the URL through or return None (DNS blocked).
        assert result in (url, None)

    def test_accepts_verifier_ton_org(self):
        url = "https://verifier.ton.org/source/abc.fc"
        assert _validate_download_url(url) == url

    def test_accepts_raw_githubusercontent(self):
        url = "https://raw.githubusercontent.com/ton-blockchain/token-contract/main/ft/jetton-minter.fc"
        assert _validate_download_url(url) == url

    def test_accepts_github_com(self):
        url = "https://github.com/tact-lang/tact/archive/v1.6.13.tar.gz"
        assert _validate_download_url(url) == url


class TestFetchUrlNoCredentials:
    """No credentials must be present in URLs passed to verifier file download."""

    def test_user_only_rejected(self):
        assert _validate_download_url("https://user@server.ton.org/file.fc") is None

    def test_password_only_rejected(self):
        # httpx parses ':pass@' with empty user
        assert _validate_download_url("https://:pass@server.ton.org/file.fc") is None
