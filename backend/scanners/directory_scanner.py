# scanners/directory_scanner.py
import requests
from typing import Dict, List
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

class DirectoryScanner:
    def __init__(self, timeout: int = 5, max_retries: int = 2):
        self.name = "directory_traversal"
        self.description = "Detecta archivos y directorios sensibles expuestos"
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Headers personalizados
        self.headers = {
            'User-Agent': 'SecurityScanner/2.0 (Directory Traversal Audit)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        
        self.session = requests.Session()
        
        # Archivos y directorios sensibles expandidos
        self.sensitive_paths = [
            # Archivos de configuración
            '.env', '.env.production', '.env.local', '.env.example',
            'config.php', 'wp-config.php', 'configuration.php',
            'database.yml', 'database.yaml', 'settings.py', 'app.config',
            'config.json', 'config.ini', 'appsettings.json',
            '.htaccess', '.htpasswd', 'web.config',
            
            # Backups y temporales
            'backup.sql', 'dump.sql', 'database.sql', 'backup.zip',
            'site.zip', 'backup.tar.gz', '.bak', '.backup', '.old', '.tmp',
            
            # Directorios administrativos
            'admin/', 'administrator/', 'wp-admin/', 'panel/', 'cpanel/',
            'phpmyadmin/', 'adminer/', 'wp-login.php', 'install.php',
            
            # Información del servidor
            'phpinfo.php', 'info.php', 'test.php', 'server-info', 'server-status',
            
            # Archivos de log
            'error.log', 'access.log', 'application.log', 'debug.log',
            
            # Archivos de desarrollo
            '.git/', '.svn/', '.idea/', '.vscode/',
            'composer.json', 'package.json', 'requirements.txt',
            'readme.txt', 'README.md', 'CHANGELOG.md',
            
            # Cloud y servicios
            'aws/credentials', '.s3cfg', '.git-credentials',
            
            # Archivos de despliegue
            'docker-compose.yml', 'Dockerfile', 'dockerfile',
            
            # Archivos de API
            'swagger.json', 'openapi.json', 'api.json',
            
            # Archivos de test
            'test.php', 'test.py', 'test.js'
        ]

    def scan(self, url: str) -> Dict:
        """Escanea directorios y archivos sensibles"""
        start_time = time.time()
        vulnerabilities = []
        
        try:
            # Normalizar URL base
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Verificar cada ruta sensible
            for path in self.sensitive_paths:
                vulnerability = self._check_path(base_url, path)
                if vulnerability:
                    vulnerabilities.append(vulnerability)
            
            # Verificar patrones adicionales
            additional_vulns = self._check_additional_patterns(base_url)
            vulnerabilities.extend(additional_vulns)
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'DIRECTORY_SCAN_ERROR',
                'severity': 'LOW',
                'description': f'Error durante escaneo de directorios: {str(e)}',
                'location': url,
                'recommendation': 'Verificar accesibilidad del sitio'
            })
        
        scan_time = time.time() - start_time
        
        # Determinar estado
        status = 'SECURE'
        if vulnerabilities:
            critical_vulns = any(vuln['severity'] in ['CRITICAL', 'HIGH'] 
                               for vuln in vulnerabilities)
            status = 'CRITICAL' if critical_vulns else 'VULNERABLE'
        
        return {
            'scanner_type': self.name,
            'url': url,
            'scan_duration': round(scan_time, 2),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'status': status,
            'timestamp': datetime.now().isoformat()
        }

    def _check_path(self, base_url: str, path: str) -> Dict:
        """Verifica si una ruta específica está accesible"""
        for attempt in range(self.max_retries):
            try:
                full_url = urljoin(base_url, path)
                response = self.session.get(
                    full_url, 
                    timeout=self.timeout, 
                    allow_redirects=False,
                    headers=self.headers
                )
                
                # Si responde con 200, está accesible
                if response.status_code == 200:
                    severity = self._determine_severity(path, response)
                    return {
                        'type': 'SENSITIVE_FILE_EXPOSED',
                        'severity': severity,
                        'description': f'Archivo/directorio sensible accesible: {path}',
                        'location': full_url,
                        'details': f'Código de respuesta: {response.status_code}, Tamaño: {len(response.content)} bytes',
                        'recommendation': self._get_recommendation(path)
                    }
                
                # Algunos servidores responden 403 pero el archivo existe
                elif response.status_code == 403 and self._is_critical_file(path):
                    return {
                        'type': 'SENSITIVE_FILE_FORBIDDEN',
                        'severity': 'MEDIUM',
                        'description': f'Archivo sensible existe pero está protegido: {path}',
                        'location': full_url,
                        'details': 'Archivo existe pero retorna 403 Forbidden',
                        'recommendation': 'Verificar que el archivo no debería estar presente en el directorio web'
                    }
                    
            except requests.RequestException:
                if attempt == self.max_retries - 1:
                    pass  # Último intento falló
                time.sleep(0.5)  # Pequeño delay entre reintentos
                
        return None

    def _check_additional_patterns(self, base_url: str) -> List[Dict]:
        """Verifica patrones adicionales de exposición"""
        vulnerabilities = []
        
        try:
            # Verificar listado de directorios con múltiples patrones
            response = self.session.get(base_url, timeout=self.timeout, headers=self.headers)
            content = response.text.lower()
            
            directory_listing_patterns = [
                'index of /', 'directory listing for', 'parent directory',
                'last modified', 'size', 'name', '<dir>', 'To Parent Directory'
            ]
            
            if any(pattern in content for pattern in directory_listing_patterns):
                vulnerabilities.append({
                    'type': 'DIRECTORY_LISTING_ENABLED',
                    'severity': 'HIGH',
                    'description': 'Listado de directorios habilitado',
                    'location': base_url,
                    'details': f'Código de respuesta: {response.status_code}',
                    'recommendation': 'Deshabilitar listado de directorios en la configuración del servidor web'
                })
            
            # Verificar robots.txt
            robots_url = urljoin(base_url, 'robots.txt')
            robots_response = self.session.get(robots_url, timeout=self.timeout, headers=self.headers)
            
            if robots_response.status_code == 200:
                robots_content = robots_response.text.lower()
                sensitive_patterns = [
                    'admin', 'private', 'secret', 'config', 'database',
                    'backup', 'install', 'setup', 'wp-admin', 'phpmyadmin'
                ]
                
                found_patterns = [
                    pattern for pattern in sensitive_patterns 
                    if pattern in robots_content
                ]
                
                if found_patterns:
                    vulnerabilities.append({
                        'type': 'SENSITIVE_INFO_IN_ROBOTS',
                        'severity': 'MEDIUM',
                        'description': 'robots.txt revela rutas sensibles',
                        'details': f'Patrones encontrados: {", ".join(found_patterns)}',
                        'location': robots_url,
                        'recommendation': 'Revisar y limpiar robots.txt de información sensible'
                    })
                    
            # Verificar sitemap.xml
            sitemap_url = urljoin(base_url, 'sitemap.xml')
            sitemap_response = self.session.get(sitemap_url, timeout=self.timeout, headers=self.headers)
            
            if sitemap_response.status_code == 200:
                sitemap_content = sitemap_response.text.lower()
                if 'admin' in sitemap_content or 'config' in sitemap_content:
                    vulnerabilities.append({
                        'type': 'SENSITIVE_INFO_IN_SITEMAP',
                        'severity': 'LOW',
                        'description': 'sitemap.xml contiene rutas sensibles',
                        'location': sitemap_url,
                        'recommendation': 'Remover rutas administrativas del sitemap.xml'
                    })
                        
        except requests.RequestException:
            pass
            
        return vulnerabilities

    def _determine_severity(self, path: str, response) -> str:
        """Determina la severidad basada en el tipo de archivo y contenido"""
        path_lower = path.lower()
        
        # Archivos CRITICAL
        critical_patterns = ['.env', 'config', 'database', 'backup', '.sql', 'credentials', 'secret']
        
        # Archivos HIGH
        high_patterns = ['admin', 'phpinfo', '.git', '.htpasswd', 'wp-config', 'install', 'login']
        
        # Archivos MEDIUM
        medium_patterns = ['log', 'readme', 'composer', 'package', 'docker', 'test']
        
        # Verificar contenido para archivos críticos
        if any(pattern in path_lower for pattern in critical_patterns):
            content = response.text if hasattr(response, 'text') else str(response.content)
            if any(keyword in content.lower() for keyword in ['password', 'secret', 'key', 'token']):
                return 'CRITICAL'
            return 'HIGH'
        
        if any(pattern in path_lower for pattern in high_patterns):
            return 'HIGH'
        
        if any(pattern in path_lower for pattern in medium_patterns):
            return 'MEDIUM'
        
        return 'LOW'

    def _is_critical_file(self, path: str) -> bool:
        """Determina si un archivo es crítico aunque esté protegido"""
        critical_files = ['.env', 'config.php', 'wp-config.php', 'database.yml', 'credentials']
        return any(critical in path.lower() for critical in critical_files)

    def _get_recommendation(self, path: str) -> str:
        """Devuelve recomendación específica según el tipo de archivo"""
        recommendations = {
            '.env': 'Mover archivo .env fuera del directorio web público. Usar variables de entorno del sistema.',
            'config': 'Mover archivos de configuración fuera del directorio público. Usar permisos restrictivos (600).',
            'backup': 'Eliminar archivos de backup del directorio web. Implementar backups automatizados en ubicación segura.',
            'admin': 'Implementar autenticación robusta (2FA), rate limiting, y IP whitelisting para paneles administrativos.',
            '.git': 'Eliminar directorio .git del servidor de producción. Verificar que no se suba accidentalmente.',
            'phpinfo': 'Eliminar archivos phpinfo.php. Usar solo en entornos de desarrollo.',
            'log': 'Mover archivos de log fuera del webroot. Configurar el servidor para que no sirva archivos .log.',
            'database': 'Nunca almacenar archivos de base de datos en el webroot. Usar sistemas de base de datos properos.'
        }
        
        path_lower = path.lower()
        for pattern, recommendation in recommendations.items():
            if pattern in path_lower:
                return recommendation
        
        return 'Implementar medidas de seguridad apropiadas: permisos restrictivos, autenticación, o remover el archivo.'

    def get_scan_summary(self, result: Dict) -> str:
        """Genera un resumen legible del escaneo"""
        summary = [
            f"🔍 Directory Traversal Scan Summary",
            f"📋 URL: {result['url']}",
            f"⏱️  Duración: {result['scan_duration']}s",
            f"📊 Estado: {result['status']}",
            f"⚠️  Archivos sensibles encontrados: {result['vulnerabilities_found']}",
            f"📅 Fecha: {result['timestamp']}",
            "",
            "📋 ARCHIVOS SENSIBLES ENCONTRADOS:"
        ]
        
        for i, vuln in enumerate(result['vulnerabilities'], 1):
            severity_emoji = {
                'CRITICAL': '🔥',
                'HIGH': '🚨', 
                'MEDIUM': '⚠️',
                'LOW': 'ℹ️'
            }.get(vuln['severity'], '❓')
            
            summary.append(
                f"{i}. {severity_emoji} [{vuln['severity']}] {vuln['description']}"
            )
        
        return "\n".join(summary)

# Ejemplo de uso
if __name__ == "__main__":
    scanner = DirectoryScanner(timeout=3, max_retries=1)
    resultado = scanner.scan("https://httpbin.org")
    
    print(scanner.get_scan_summary(resultado))
    
    for vuln in resultado['vulnerabilities']:
        print(f"\n{vuln['description']}")
        print(f"   Recomendación: {vuln['recommendation']}")