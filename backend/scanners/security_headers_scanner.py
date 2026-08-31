# scanners/security_headers_scanner.py
import requests
from typing import Dict, List
import time
from datetime import datetime
import re

class SecurityHeadersScanner:
    def __init__(self):
        self.name = "security_headers"
        self.description = "Analiza headers de seguridad HTTP"
        
        # Headers críticos que debe tener todo sitio web
        self.required_headers = {
            'X-Content-Type-Options': {
                'expected': 'nosniff',
                'description': 'Previene MIME sniffing attacks',
                'severity': 'MEDIUM'
            },
            'X-Frame-Options': {
                'expected': ['DENY', 'SAMEORIGIN'],
                'description': 'Previene ataques de clickjacking',
                'severity': 'HIGH'
            },
            'X-XSS-Protection': {
                'expected': '1; mode=block',
                'description': 'Activa protección XSS del navegador',
                'severity': 'MEDIUM'
            },
            'Strict-Transport-Security': {
                'expected': None,
                'description': 'Fuerza conexiones HTTPS',
                'severity': 'HIGH'
            },
            'Content-Security-Policy': {
                'expected': None,
                'description': 'Previene ataques XSS y injection',
                'severity': 'HIGH'
            },
            'Referrer-Policy': {
                'expected': ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin'],
                'description': 'Controla información del referrer',
                'severity': 'LOW'
            },
            'Permissions-Policy': {
                'expected': None,
                'description': 'Controla características del navegador (cámara, micrófono, etc)',
                'severity': 'MEDIUM'
            },
            'Cross-Origin-Embedder-Policy': {
                'expected': None,
                'description': 'Protege contra ataques de espectador',
                'severity': 'MEDIUM'
            },
            'Cross-Origin-Opener-Policy': {
                'expected': None,
                'description': 'Aísla ventanas entre sitios diferentes',
                'severity': 'MEDIUM'
            }
        }

    def scan(self, url: str) -> Dict:
        """Escanea headers de seguridad de una URL"""
        start_time = time.time()
        vulnerabilities = []
        
        # Headers personalizados para la solicitud
        request_headers = {
            'User-Agent': 'SecurityHeadersScanner/2.0 (Security Audit Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        
        try:
            # Hacer petición HTTP con headers personalizados
            response = requests.get(
                url, 
                timeout=15, 
                allow_redirects=True, 
                headers=request_headers,
                verify=True  # Verificar certificados SSL
            )
            
            headers = response.headers
            final_url = response.url  # URL final después de redirects
            
            # Analizar cada header requerido
            for header_name, config in self.required_headers.items():
                vulnerability = self._check_header(header_name, headers, config)
                if vulnerability:
                    vulnerabilities.append(vulnerability)
            
            # Verificar headers peligrosos que NO deberían estar
            dangerous_headers = self._check_dangerous_headers(headers)
            vulnerabilities.extend(dangerous_headers)
            
            # Verificación especial para CSP
            csp_vuln = self._check_csp_policy(headers)
            if csp_vuln:
                vulnerabilities.append(csp_vuln)
                
            # Verificación especial para HSTS
            hsts_vuln = self._check_hsts_policy(headers)
            if hsts_vuln:
                vulnerabilities.append(hsts_vuln)
            
        except requests.exceptions.SSLError as e:
            vulnerabilities.append({
                'type': 'SSL_CERTIFICATE_ERROR',
                'severity': 'HIGH',
                'description': 'Error de certificado SSL/TLS',
                'details': f'Error: {str(e)}',
                'location': url,
                'recommendation': 'Verificar y corregir la configuración SSL del servidor'
            })
            
        except requests.exceptions.Timeout:
            vulnerabilities.append({
                'type': 'CONNECTION_TIMEOUT',
                'severity': 'MEDIUM',
                'description': 'Timeout al conectar con el servidor',
                'location': url,
                'recommendation': 'El servidor no respondió en el tiempo esperado. Verificar disponibilidad.'
            })
            
        except requests.exceptions.RequestException as e:
            vulnerabilities.append({
                'type': 'CONNECTION_ERROR',
                'severity': 'HIGH',
                'description': f'Error al conectar con el sitio: {str(e)}',
                'location': url,
                'recommendation': 'Verificar que el sitio esté accesible y la URL sea correcta'
            })
        
        scan_time = time.time() - start_time
        
        # Determinar estado general
        status = 'SECURE'
        if vulnerabilities:
            # Verificar si hay vulnerabilidades críticas
            critical_vulns = any(vuln['severity'] in ['HIGH', 'CRITICAL'] 
                               for vuln in vulnerabilities)
            status = 'CRITICAL' if critical_vulns else 'VULNERABLE'
        
        return {
            'scanner_type': self.name,
            'original_url': url,
            'final_url': response.url if 'response' in locals() else url,
            'scan_duration': round(scan_time, 2),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'http_status': response.status_code if 'response' in locals() else 'N/A',
            'server_info': headers.get('Server', 'No identificado') if 'response' in locals() else 'N/A'
        }

    def _check_header(self, header_name: str, headers: Dict, config: Dict) -> Dict:
        """Verifica un header específico"""
        if header_name not in headers:
            return {
                'type': 'MISSING_SECURITY_HEADER',
                'severity': config['severity'],
                'description': f'Falta header de seguridad: {header_name}',
                'details': config['description'],
                'location': 'HTTP Headers',
                'recommendation': f'Agregar header {header_name} al servidor web. {config["description"]}'
            }
        
        header_value = headers[header_name]
        expected = config['expected']
        
        # Si hay valores esperados específicos, verificarlos
        if expected and isinstance(expected, list):
            if header_value not in expected:
                return {
                    'type': 'WEAK_SECURITY_HEADER',
                    'severity': config['severity'],
                    'description': f'Header {header_name} tiene valor débil: {header_value}',
                    'details': f'Valores recomendados: {", ".join(expected)}. {config["description"]}',
                    'location': 'HTTP Headers',
                    'recommendation': f'Cambiar valor de {header_name} a uno más seguro. Valores recomendados: {", ".join(expected)}'
                }
        elif expected and isinstance(expected, str):
            if header_value != expected:
                return {
                    'type': 'WEAK_SECURITY_HEADER',
                    'severity': config['severity'],
                    'description': f'Header {header_name} no tiene el valor recomendado',
                    'details': f'Actual: {header_value}, Recomendado: {expected}. {config["description"]}',
                    'location': 'HTTP Headers',
                    'recommendation': f'Cambiar {header_name} a: {expected}. {config["description"]}'
                }
        
        return None

    def _check_csp_policy(self, headers: Dict) -> Dict:
        """Verificación especial para Content-Security-Policy"""
        if 'Content-Security-Policy' not in headers:
            return None
            
        csp_value = headers['Content-Security-Policy']
        
        # Detectar directivas inseguras
        insecure_directives = []
        
        if 'unsafe-inline' in csp_value:
            insecure_directives.append('unsafe-inline')
        if 'unsafe-eval' in csp_value:
            insecure_directives.append('unsafe-eval')
        if "'self'" not in csp_value and 'none' not in csp_value.lower():
            insecure_directives.append('missing self/none')
            
        if insecure_directives:
            return {
                'type': 'WEAK_CSP_POLICY',
                'severity': 'MEDIUM',
                'description': 'Content-Security-Policy contiene directivas inseguras',
                'details': f'Directivas problemáticas: {", ".join(insecure_directives)}. CSP completo: {csp_value}',
                'location': 'HTTP Headers',
                'recommendation': 'Eliminar unsafe-inline y unsafe-eval. Usar nonces o hashes en su lugar. Incluir \'self\' para restringir al mismo origen.'
            }
            
        return None

    def _check_hsts_policy(self, headers: Dict) -> Dict:
        """Verificación especial para Strict-Transport-Security"""
        if 'Strict-Transport-Security' not in headers:
            return None
            
        hsts_value = headers['Strict-Transport-Security']
        
        # Verificar max-age=0 (deshabilitado)
        if 'max-age=0' in hsts_value:
            return {
                'type': 'WEAK_HSTS_POLICY',
                'severity': 'HIGH',
                'description': 'HSTS tiene max-age=0 (deshabilitado)',
                'details': f'Valor HSTS: {hsts_value}',
                'location': 'HTTP Headers',
                'recommendation': 'Configurar max-age mínimo de 31536000 segundos (1 año). Eliminar max-age=0.'
            }
        
        # Extraer y verificar max-age
        match = re.search(r'max-age=(\d+)', hsts_value)
        if match:
            max_age = int(match.group(1))
            
            if max_age < 2592000:  # Menos de 30 días
                return {
                    'type': 'SHORT_HSTS_MAX_AGE',
                    'severity': 'MEDIUM',
                    'description': f'HSTS tiene max-age muy corto ({max_age} segundos)',
                    'details': f'Recomendado mínimo: 2592000 segundos (30 días). Ideal: 31536000 (1 año). Valor actual: {hsts_value}',
                    'location': 'HTTP Headers',
                    'recommendation': 'Configurar max-age mínimo de 31536000 segundos (1 año) para mejor seguridad.'
                }
        
        # Verificar si incluye includeSubDomains y preload
        if 'includeSubDomains' not in hsts_value:
            return {
                'type': 'HSTS_MISSING_SUBDOMAINS',
                'severity': 'LOW',
                'description': 'HSTS no incluye includeSubDomains',
                'details': 'Los subdominios no están protegidos por HSTS',
                'location': 'HTTP Headers',
                'recommendation': 'Agregar includeSubDomains al header HSTS para proteger todos los subdominios'
            }
            
        return None

    def _check_dangerous_headers(self, headers: Dict) -> List[Dict]:
        """Verifica headers que pueden revelar información sensible"""
        dangerous = []
        
        # Headers que revelan información del servidor
        sensitive_headers = {
            'Server': 'Revela información del servidor web',
            'X-Powered-By': 'Revela tecnología backend utilizada',
            'X-AspNet-Version': 'Revela versión de ASP.NET',
            'X-AspNetMvc-Version': 'Revela versión de ASP.NET MVC',
            'X-PHP-Version': 'Revela versión de PHP',
            'X-Runtime': 'Revela información del runtime (Ruby, etc)',
            'X-Backend-Server': 'Revela información del backend',
            'X-Generator': 'Revela tecnología de generación de contenido',
            'X-Drupal-Cache': 'Revela uso de Drupal'
        }
        
        for header, description in sensitive_headers.items():
            if header in headers:
                dangerous.append({
                    'type': 'INFORMATION_DISCLOSURE',
                    'severity': 'LOW',
                    'description': f'Header revela información sensible: {header}',
                    'details': f'{description}. Valor: {headers[header]}',
                    'location': 'HTTP Headers',
                    'recommendation': f'Remover o ocultar header {header} del servidor web'
                })
        
        return dangerous

    def get_scan_summary(self, result: Dict) -> str:
        """Genera un resumen legible del escaneo"""
        summary = [
            f"🔍 Security Headers Scan Summary",
            f"📋 URL: {result['original_url']}",
            f"🔗 Final URL: {result.get('final_url', 'N/A')}",
            f"⏱️  Duración: {result['scan_duration']}s",
            f"📊 Estado: {result['status']}",
            f"⚠️  Vulnerabilidades: {result['vulnerabilities_found']}",
            f"🖥️  Servidor: {result.get('server_info', 'N/A')}",
            f"📅 Fecha: {result['timestamp']}",
            "",
            "📋 VULNERABILIDADES ENCONTRADAS:"
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
    # Ejemplo rápido de uso
    scanner = SecurityHeadersScanner()
    
    # Escanear un sitio
    resultado = scanner.scan("https://httpbin.org/headers")
    
    # Imprimir resumen
    print(scanner.get_scan_summary(resultado))
    
    # Mostrar detalles completos
    print(f"\n📄 Detalles completos:")
    for vuln in resultado['vulnerabilities']:
        print(f"\n{vuln['description']}")
        print(f"   Recomendación: {vuln['recommendation']}")