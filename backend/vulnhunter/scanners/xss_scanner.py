"""Conservative reflected-XSS checks.

Plain text reflection is not proof of XSS. A finding is emitted only when the
injected marker is parsed back as an event-bearing HTML element.
"""

from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


class XSSScanner:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "VulnHunter/0.1 (authorized security assessment)"}
        )

    @staticmethod
    def _payload(token: str) -> str:
        return f'\"><svg data-vh-token="{token}" onload="alert(\'{token}\')">'

    @staticmethod
    def _has_executable_injection(html: str, token: str) -> bool:
        soup = BeautifulSoup(html, "html.parser")
        for element in soup.find_all(attrs={"data-vh-token": token}):
            for attribute, value in element.attrs.items():
                if attribute.lower().startswith("on") and token in str(value):
                    return True
        return False

    def scan_url(self, target_url: str) -> Dict:
        started = time.time()
        results = {
            "url": target_url,
            "vulnerable": False,
            "vulnerabilities": [],
            "forms_found": 0,
            "params_tested": 0,
            "scan_time": None,
            "error": None,
        }
        try:
            response = self.session.get(target_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            results["forms_found"] = len(forms)

            for form in forms:
                finding, tested = self._test_form_xss(target_url, form)
                results["params_tested"] += tested
                if finding:
                    results["vulnerabilities"].append(finding)

            findings, tested = self._test_existing_get_parameters(target_url)
            results["params_tested"] += tested
            results["vulnerabilities"].extend(findings)
            results["vulnerable"] = bool(results["vulnerabilities"])
        except requests.RequestException as exc:
            results["error"] = f"Error de conexión: {exc}"
        except Exception as exc:
            results["error"] = f"Error inesperado: {exc}"

        results["scan_time"] = round(time.time() - started, 2)
        return results

    def _test_form_xss(self, base_url: str, form) -> tuple[Optional[Dict], int]:
        action_url = urljoin(base_url, form.get("action", ""))
        if urlparse(action_url).netloc != urlparse(base_url).netloc:
            return None, 0

        method = form.get("method", "get").lower()
        if method not in {"get", "post"}:
            return None, 0

        form_data: dict[str, str] = {}
        testable: list[str] = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            field_type = field.get("type", "text").lower()
            if field_type in {"submit", "button", "file", "password", "reset"}:
                continue
            form_data[name] = field.get("value", "test")
            if field_type != "hidden":
                testable.append(name)

        tested = 0
        for field_name in testable:
            token = f"vhxss{uuid.uuid4().hex}"
            data = dict(form_data)
            data[field_name] = self._payload(token)
            try:
                if method == "post":
                    response = self.session.post(action_url, data=data, timeout=10)
                else:
                    response = self.session.get(action_url, params=data, timeout=10)
                tested += 1
                if self._has_executable_injection(response.text, token):
                    return self._finding(response.url, field_name, method.upper(), token), tested
            except requests.RequestException:
                continue
        return None, tested

    def _test_existing_get_parameters(self, target_url: str) -> tuple[List[Dict], int]:
        """Test existing parameters only; guessed parameters inflate false positives."""
        parsed = urlparse(target_url)
        existing = parse_qsl(parsed.query, keep_blank_values=True)
        findings: list[Dict] = []
        tested = 0
        for index, (name, _value) in enumerate(existing):
            token = f"vhxss{uuid.uuid4().hex}"
            params = list(existing)
            params[index] = (name, self._payload(token))
            test_url = urlunparse(parsed._replace(query=urlencode(params)))
            try:
                response = self.session.get(test_url, timeout=10)
                tested += 1
                if self._has_executable_injection(response.text, token):
                    findings.append(self._finding(response.url, name, "GET", token))
            except requests.RequestException:
                continue
        return findings, tested

    @staticmethod
    def _finding(location: str, field: str, method: str, token: str) -> Dict:
        return {
            "type": "REFLECTED_XSS",
            "location": location,
            "field": field,
            "method": method,
            "severity": "HIGH",
            "confidence": "high",
            "evidence": f"El marcador {token} fue interpretado como un elemento SVG con manejador onload.",
            "description": "La entrada controlada fue reflejada en un contexto HTML ejecutable.",
            "recommendation": "Codificar la salida según su contexto y aplicar una CSP restrictiva como defensa adicional.",
        }
