from requests.structures import CaseInsensitiveDict

from vulnhunter.scanners.directory_scanner import DirectoryScanner
from vulnhunter.scanners.security_headers_scanner import SecurityHeadersScanner
from vulnhunter.scanners.sql_injection_scanner import SQLInjectionScanner
from vulnhunter.scanners.xss_scanner import XSSScanner


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None, url="https://example.test/"):
        self.text = text
        self.content = text.encode()
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers or {"Content-Type": "text/html"})
        self.url = url


def test_xss_plain_or_escaped_reflection_is_not_executable():
    token = "vhxss123"
    plain = f"<p>{token}</p>"
    escaped = f"&lt;svg data-vh-token=&quot;{token}&quot; onload=&quot;alert(1)&quot;&gt;"

    assert XSSScanner._has_executable_injection(plain, token) is False
    assert XSSScanner._has_executable_injection(escaped, token) is False


def test_xss_requires_injected_event_bearing_element():
    token = "vhxss123"
    html = f'<svg data-vh-token="{token}" onload="alert(\'{token}\')"></svg>'

    assert XSSScanner._has_executable_injection(html, token) is True


def test_sqli_does_not_treat_size_or_status_change_as_confirmation():
    scanner = SQLInjectionScanner()
    baseline = FakeResponse("normal", 200)
    attack = FakeResponse("validation rejected " * 100, 500)

    result = scanner._analyze_response_for_sqli(
        attack, baseline, "'", {"type": "test", "location": "https://example.test"}
    )

    assert result is None


def test_sqli_requires_new_database_specific_error():
    scanner = SQLInjectionScanner()
    baseline = FakeResponse("normal response")
    attack = FakeResponse("You have an error in your SQL syntax near quote")

    result = scanner._analyze_response_for_sqli(
        attack, baseline, "'", {"type": "test", "location": "https://example.test"}
    )

    assert result is not None
    assert result["confidence"] == "high"


def test_sqli_ignores_database_error_already_present_in_baseline():
    scanner = SQLInjectionScanner()
    text = "You have an error in your SQL syntax"

    assert scanner._analyze_response_for_sqli(
        FakeResponse(text), FakeResponse(text), "'", {"type": "test"}
    ) is None


def test_directory_scanner_recognizes_spa_soft_404():
    baseline = FakeResponse("<html><div id='app'>Page 839102 not found</div></html>")
    candidate = FakeResponse("<html><div id='app'>Page 557733 not found</div></html>")

    assert DirectoryScanner._looks_like_soft_404(candidate, baseline) is True


def test_directory_scanner_requires_content_evidence():
    html = FakeResponse("<html><title>Welcome</title></html>")
    env = FakeResponse("DATABASE_URL=postgresql://db\nSECRET_KEY=value")

    assert DirectoryScanner._content_evidence(".env", html) is None
    assert DirectoryScanner._content_evidence(".env", env) is not None


def test_security_headers_accepts_csp_clickjacking_alternative_and_ignores_obsolete_headers():
    scanner = SecurityHeadersScanner()
    headers = CaseInsensitiveDict({
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000",
        "Server": "nginx",
    })

    findings = scanner._core_header_findings(headers, is_https=True)
    assert findings == []
    assert scanner._check_csp_policy(headers) is None
    assert scanner._check_hsts_policy(headers) is None
    assert scanner._check_version_disclosure(headers) == []


def test_security_headers_only_reports_concrete_server_version():
    scanner = SecurityHeadersScanner()

    assert scanner._check_version_disclosure(CaseInsensitiveDict({"Server": "nginx"})) == []
    assert len(scanner._check_version_disclosure(CaseInsensitiveDict({"Server": "nginx/1.25.4"}))) == 1
