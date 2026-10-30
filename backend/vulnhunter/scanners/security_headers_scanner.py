"""Context-aware HTTP security-header assessment."""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests


class SecurityHeadersScanner:
    def __init__(self) -> None:
        self.name = "security_headers"
        self.description = "Analiza controles HTTP aplicables al contexto de la respuesta"

    def scan(self, url: str) -> Dict:
        started = time.time()
        findings: list[Dict] = []
        error: Optional[str] = None
        response = None
        try:
            response = requests.get(
                url,
                timeout=15,
                allow_redirects=True,
                headers={"User-Agent": "VulnHunter/0.1 (authorized security assessment)"},
                verify=True,
            )
            headers = response.headers
            final_url = response.url
            is_https = urlparse(final_url).scheme.lower() == "https"

            findings.extend(self._core_header_findings(headers, is_https))
            csp = self._check_csp_policy(headers)
            if csp:
                findings.append(csp)
            if is_https:
                hsts = self._check_hsts_policy(headers)
                if hsts:
                    findings.append(hsts)
            findings.extend(self._check_version_disclosure(headers))
        except requests.RequestException as exc:
            # Connectivity/certificate failures are scanner errors, not evidence
            # that the requested security header is missing.
            error = f"No se pudieron evaluar los headers: {exc}"

        status = "VULNERABLE" if findings else ("ERROR" if error else "SECURE")
        headers = response.headers if response is not None else {}
        return {
            "scanner_type": self.name,
            "original_url": url,
            "final_url": response.url if response is not None else url,
            "scan_duration": round(time.time() - started, 2),
            "vulnerabilities_found": len(findings),
            "vulnerabilities": findings,
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "http_status": response.status_code if response is not None else "N/A",
            "server_info": headers.get("Server", "No identificado"),
            "error": error,
        }

    def _core_header_findings(self, headers: Dict, is_https: bool) -> List[Dict]:
        findings: list[Dict] = []
        nosniff = headers.get("X-Content-Type-Options", "")
        if nosniff.lower().strip() != "nosniff":
            findings.append(self._missing_or_weak(
                "X-Content-Type-Options", "LOW",
                "Configurar X-Content-Type-Options: nosniff.",
            ))

        csp = headers.get("Content-Security-Policy", "")
        frame_ancestors = re.search(r"(?:^|;)\s*frame-ancestors\s+[^;]+", csp, re.I)
        x_frame = headers.get("X-Frame-Options", "").upper().strip()
        if not frame_ancestors and x_frame not in {"DENY", "SAMEORIGIN"}:
            findings.append(self._missing_or_weak(
                "protección anti-clickjacking", "MEDIUM",
                "Definir frame-ancestors en CSP o X-Frame-Options: DENY/SAMEORIGIN.",
            ))

        if not csp:
            findings.append(self._missing_or_weak(
                "Content-Security-Policy", "MEDIUM",
                "Definir una CSP adaptada a los recursos reales de la aplicación.",
            ))

        referrer = headers.get("Referrer-Policy", "").lower()
        accepted = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
        if not any(value in accepted for value in re.split(r"\s*,\s*", referrer) if value):
            findings.append(self._missing_or_weak(
                "Referrer-Policy", "LOW",
                "Usar no-referrer, same-origin, strict-origin o strict-origin-when-cross-origin.",
            ))

        if is_https and "Strict-Transport-Security" not in headers:
            findings.append(self._missing_or_weak(
                "Strict-Transport-Security", "MEDIUM",
                "Publicar HSTS sobre HTTPS con un max-age probado progresivamente.",
            ))
        return findings

    @staticmethod
    def _missing_or_weak(control: str, severity: str, recommendation: str) -> Dict:
        return {
            "type": "MISSING_OR_WEAK_SECURITY_HEADER",
            "severity": severity,
            "confidence": "high",
            "description": f"Control HTTP ausente o débil: {control}",
            "location": "HTTP Headers",
            "evidence": f"La respuesta efectiva no contiene una configuración válida para {control}.",
            "recommendation": recommendation,
        }

    @staticmethod
    def _check_csp_policy(headers: Dict) -> Optional[Dict]:
        value = headers.get("Content-Security-Policy")
        if not value:
            return None
        lower = value.lower()
        problems: list[str] = []
        has_nonce_or_hash = bool(re.search(r"'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'", lower))
        if "'unsafe-eval'" in lower:
            problems.append("unsafe-eval")
        if "'unsafe-inline'" in lower and not has_nonce_or_hash:
            problems.append("unsafe-inline sin nonce/hash")
        if re.search(r"(?:^|;)\s*(?:default-src|script-src)\s+\*", lower):
            problems.append("origen comodín para scripts")
        if not problems:
            return None
        return {
            "type": "WEAK_CSP_POLICY",
            "severity": "MEDIUM",
            "confidence": "high",
            "description": "La política CSP permite ejecución de scripts con controles débiles.",
            "location": "HTTP Headers",
            "evidence": f"Directivas observadas: {', '.join(problems)}.",
            "recommendation": "Eliminar unsafe-eval y sustituir inline scripts por nonces o hashes; restringir script-src.",
        }

    @staticmethod
    def _check_hsts_policy(headers: Dict) -> Optional[Dict]:
        value = headers.get("Strict-Transport-Security")
        if not value:
            return None
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.I)
        if not match:
            problem = "max-age ausente o inválido"
        elif int(match.group(1)) == 0:
            problem = "max-age=0 deshabilita HSTS"
        elif int(match.group(1)) < 2_592_000:
            problem = "max-age inferior a 30 días"
        else:
            return None
        return {
            "type": "WEAK_HSTS_POLICY",
            "severity": "MEDIUM",
            "confidence": "high",
            "description": "La política HSTS no ofrece persistencia suficiente.",
            "location": "HTTP Headers",
            "evidence": problem,
            "recommendation": "Aumentar max-age gradualmente hasta al menos 31536000 después de validar HTTPS.",
        }

    @staticmethod
    def _check_version_disclosure(headers: Dict) -> List[Dict]:
        findings: list[Dict] = []
        for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-PHP-Version"):
            value = headers.get(name)
            if not value or not re.search(r"\d+(?:\.\d+)+", value):
                continue
            findings.append({
                "type": "SOFTWARE_VERSION_DISCLOSURE",
                "severity": "LOW",
                "confidence": "high",
                "description": f"El header {name} expone una versión concreta de software.",
                "location": "HTTP Headers",
                "evidence": f"{name}: {value[:120]}",
                "recommendation": f"Ocultar el detalle de versión del header {name} cuando sea posible.",
            })
        return findings

    def get_scan_summary(self, result: Dict) -> str:
        return (
            f"Security Headers: {result['original_url']}\n"
            f"Estado: {result['status']}\n"
            f"Hallazgos: {result['vulnerabilities_found']}"
        )
