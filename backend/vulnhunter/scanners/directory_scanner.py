"""Evidence-based checks for accidentally exposed sensitive files."""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime
from difflib import SequenceMatcher
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests


class DirectoryScanner:
    def __init__(self, timeout: int = 5, max_retries: int = 2) -> None:
        self.name = "sensitive_file_exposure"
        self.description = "Detecta archivos sensibles expuestos con evidencia de contenido"
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = {
            "User-Agent": "VulnHunter/0.1 (authorized security assessment)",
            "Accept": "*/*",
            "Connection": "close",
        }
        self.session = requests.Session()
        # Login/admin pages, robots.txt, package manifests and API docs are not
        # vulnerabilities by themselves and intentionally are not included.
        self.sensitive_paths = [
            ".env", ".env.production", ".env.local",
            "config.php", "wp-config.php", "configuration.php",
            "database.yml", "database.yaml", "settings.py", "appsettings.json",
            ".htpasswd", "backup.sql", "dump.sql", "database.sql",
            "backup.zip", "site.zip", "backup.tar.gz",
            "phpinfo.php", "info.php", "server-status",
            "error.log", "application.log", "debug.log",
            ".git/config", ".svn/entries", "aws/credentials", ".git-credentials",
            "docker-compose.yml", "Dockerfile",
        ]

    def scan(self, url: str) -> Dict:
        started = time.time()
        vulnerabilities: list[Dict] = []
        error: Optional[str] = None
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"

        try:
            baseline_url = urljoin(base_url, f".vulnhunter-not-found-{uuid.uuid4().hex}")
            baseline = self.session.get(
                baseline_url,
                timeout=self.timeout,
                allow_redirects=False,
                headers=self.headers,
            )
            for path in self.sensitive_paths:
                finding = self._check_path(base_url, path, baseline)
                if finding:
                    vulnerabilities.append(finding)
            listing = self._check_directory_listing(base_url)
            if listing:
                vulnerabilities.append(listing)
        except requests.RequestException as exc:
            error = f"No se pudo completar el escaneo de archivos sensibles: {exc}"

        status = "VULNERABLE" if vulnerabilities else ("ERROR" if error else "SECURE")
        return {
            "scanner_type": self.name,
            "url": url,
            "scan_duration": round(time.time() - started, 2),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "error": error,
        }

    def _check_path(self, base_url: str, path: str, baseline) -> Optional[Dict]:
        full_url = urljoin(base_url, path)
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(
                    full_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers=self.headers,
                )
                if response.status_code != 200:
                    return None
                if self._looks_like_soft_404(response, baseline):
                    return None
                evidence = self._content_evidence(path, response)
                if not evidence:
                    return None
                return {
                    "type": "SENSITIVE_FILE_EXPOSED",
                    "severity": self._determine_severity(path, evidence),
                    "confidence": "high",
                    "description": f"Archivo sensible expuesto con contenido corroborado: {path}",
                    "location": full_url,
                    "evidence": evidence,
                    "details": f"HTTP 200; tipo de contenido: {response.headers.get('Content-Type', 'desconocido')}",
                    "recommendation": self._get_recommendation(path),
                }
            except requests.RequestException:
                if attempt + 1 < self.max_retries:
                    time.sleep(0.2)
        return None

    @classmethod
    def _looks_like_soft_404(cls, response, baseline) -> bool:
        if response.status_code != baseline.status_code:
            return False
        left = cls._normalize_body(response.text)
        right = cls._normalize_body(baseline.text)
        if not left or not right:
            return False
        same_type = response.headers.get("Content-Type", "").split(";", 1)[0] == baseline.headers.get(
            "Content-Type", ""
        ).split(";", 1)[0]
        return same_type and SequenceMatcher(None, left, right).ratio() >= 0.90

    @staticmethod
    def _normalize_body(body: str) -> str:
        body = re.sub(r"[0-9a-f]{16,}", "<token>", body.lower())
        body = re.sub(r"\d+", "<n>", body)
        return re.sub(r"\s+", " ", body).strip()[:100_000]

    @staticmethod
    def _content_evidence(path: str, response) -> Optional[str]:
        lower_path = path.lower()
        text = response.text[:500_000]
        lower = text.lower()
        raw = response.content[:8]

        if lower_path.endswith((".zip", ".tar.gz")):
            if raw.startswith(b"PK\x03\x04") or raw.startswith(b"\x1f\x8b"):
                return "La respuesta contiene la firma binaria de un archivo comprimido."
            return None
        if ".env" in lower_path:
            return "Formato KEY=VALUE detectado." if re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", text) else None
        if lower_path.endswith(".sql"):
            return "Sentencias SQL detectadas." if re.search(r"(?i)\b(create\s+table|insert\s+into|pg_dump|mysqldump)\b", text) else None
        if lower_path == ".git/config":
            return "Metadatos de repositorio Git detectados." if "[core]" in lower and "repositoryformatversion" in lower else None
        if lower_path == ".svn/entries":
            return "Metadatos de Subversion detectados." if ("svn" in lower or "dir\n" in lower) else None
        if "credentials" in lower_path or lower_path.endswith(".htpasswd"):
            patterns = [r"(?m)^\[[^]]+\]", r"(?m)^aws_access_key_id\s*=", r"(?m)^[^:\s]+:\$[0-9a-z]+\$"]
            return "Formato de credenciales detectado." if any(re.search(p, text, re.I) for p in patterns) else None
        if lower_path.endswith((".php", ".py", ".yml", ".yaml", ".json")) or "config" in lower_path:
            config_words = sum(word in lower for word in ("password", "database", "secret", "api_key", "db_host"))
            return "Contenido de configuración sensible detectado." if config_words >= 2 else None
        if lower_path.endswith(".log"):
            return "Formato de log o stack trace detectado." if re.search(r"(?i)(traceback|exception|\berror\b|\d{4}-\d{2}-\d{2})", text) else None
        if "phpinfo" in lower_path or lower_path == "info.php":
            return "Salida de phpinfo() detectada." if "php version" in lower and "phpinfo()" in lower else None
        if lower_path == "server-status":
            return "Página de estado de Apache detectada." if "apache server status" in lower else None
        if lower_path.endswith("docker-compose.yml"):
            return "Manifiesto Docker Compose detectado." if re.search(r"(?m)^services\s*:", text) else None
        if lower_path.endswith("dockerfile"):
            return "Dockerfile detectado." if re.search(r"(?mi)^from\s+\S+", text) else None
        return None

    def _check_directory_listing(self, base_url: str) -> Optional[Dict]:
        try:
            response = self.session.get(base_url, timeout=self.timeout, headers=self.headers)
            if response.status_code != 200:
                return None
            content = response.text.lower()
            strong_signals = (
                "<title>index of /" in content
                and "parent directory" in content
                and ("last modified" in content or "directory listing for" in content)
            )
            if not strong_signals:
                return None
            return {
                "type": "DIRECTORY_LISTING_ENABLED",
                "severity": "MEDIUM",
                "confidence": "high",
                "description": "El servidor publica un índice de archivos del directorio raíz.",
                "location": base_url,
                "evidence": "Se observaron conjuntamente título Index of, Parent Directory y columnas de listado.",
                "recommendation": "Deshabilitar el listado de directorios en el servidor web.",
            }
        except requests.RequestException:
            return None

    @staticmethod
    def _determine_severity(path: str, evidence: str) -> str:
        path = path.lower()
        if path.endswith(".sql"):
            return "CRITICAL"
        if any(value in path for value in (".env", "credentials", ".htpasswd", "backup", "config", ".git", "phpinfo", "server-status")):
            return "HIGH"
        return "LOW"

    @staticmethod
    def _get_recommendation(path: str) -> str:
        if ".git" in path.lower():
            return "Excluir el directorio .git del despliegue y bloquear su acceso desde el servidor web."
        if ".env" in path.lower() or "credentials" in path.lower():
            return "Retirar las credenciales del webroot, rotarlas y almacenarlas en un gestor de secretos."
        if "backup" in path.lower() or path.lower().endswith(".sql"):
            return "Eliminar el respaldo del webroot y conservarlo en almacenamiento privado cifrado."
        return "Retirar el archivo del webroot o denegar explícitamente su publicación."

    def get_scan_summary(self, result: Dict) -> str:
        return (
            f"Sensitive File Scan: {result['url']}\n"
            f"Estado: {result['status']}\n"
            f"Hallazgos confirmados: {result['vulnerabilities_found']}"
        )
