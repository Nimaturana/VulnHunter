# scanners/ssl_scanner.py
import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime
import time
from typing import Dict, List

class SSLScanner:
    def __init__(self):
        self.name = "ssl_analysis"
        self.description = "Analiza certificados SSL/TLS y configuración"
        
        # Versiones de protocolo seguras
        self.secure_protocols = ['TLSv1.2', 'TLSv1.3']
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']

    def scan(self, url: str) -> Dict:
        """Escanea configuración SSL/TLS de una URL"""
        start_time = time.time()
        vulnerabilities = []
        
        try:
            parsed_url = urlparse(url)
            
            # Solo analizar HTTPS
            if parsed_url.scheme != 'https':
                vulnerabilities.append({
                    'type': 'NO_HTTPS',
                    'severity': 'HIGH',
                    'description': 'El sitio no usa HTTPS',
                    'location': url,
                    'recommendation': 'Implementar certificado SSL y redireccionar HTTP a HTTPS'
                })
                
                return self._build_result(url, time.time() - start_time, vulnerabilities)
            
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Obtener información del certificado
            cert_info = self._get_certificate_info(hostname, port)
            if cert_info.get('vulnerabilities'):
                vulnerabilities.extend(cert_info['vulnerabilities'])
            
            # Verificar configuración SSL
            ssl_config = self._check_ssl_configuration(hostname, port)
            if ssl_config.get('vulnerabilities'):
                vulnerabilities.extend(ssl_config['vulnerabilities'])
            
            # Verificar redirección HTTP a HTTPS
            redirect_check = self._check_http_redirect(parsed_url)
            if redirect_check.get('vulnerabilities'):
                vulnerabilities.extend(redirect_check['vulnerabilities'])
                
        except Exception as e:
            vulnerabilities.append({
                'type': 'SSL_SCAN_ERROR',
                'severity': 'MEDIUM',
                'description': f'Error al escanear SSL: {str(e)}',
                'location': url,
                'recommendation': 'Verificar que el certificado SSL esté correctamente configurado'
            })
        
        return self._build_result(url, time.time() - start_time, vulnerabilities)

    def _get_certificate_info(self, hostname: str, port: int) -> Dict:
        """Obtiene información del certificado SSL"""
        vulnerabilities = []
        
        try:
            # Crear contexto SSL
            context = ssl.create_default_context()
            
            # Conectar y obtener certificado
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Verificar expiración
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry <= 0:
                        vulnerabilities.append({
                            'type': 'EXPIRED_CERTIFICATE',
                            'severity': 'CRITICAL',
                            'description': 'Certificado SSL expirado',
                            'details': f'Expiró el: {cert["notAfter"]}',
                            'location': f'{hostname}:{port}',
                            'recommendation': 'Renovar certificado SSL inmediatamente'
                        })
                    elif days_until_expiry <= 30:
                        vulnerabilities.append({
                            'type': 'CERTIFICATE_EXPIRING_SOON',
                            'severity': 'HIGH',
                            'description': f'Certificado SSL expira en {days_until_expiry} días',
                            'details': f'Expira el: {cert["notAfter"]}',
                            'location': f'{hostname}:{port}',
                            'recommendation': 'Renovar certificado SSL antes de que expire'
                        })
                    
                    # Verificar nombre del certificado
                    if not self._verify_hostname(cert, hostname):
                        vulnerabilities.append({
                            'type': 'HOSTNAME_MISMATCH',
                            'severity': 'HIGH',
                            'description': 'El certificado no coincide con el hostname',
                            'location': f'{hostname}:{port}',
                            'recommendation': 'Usar certificado que coincida con el dominio'
                        })
                    
                    # Verificar algoritmo de firma
                    if cert.get('signatureAlgorithm', '').lower().startswith('sha1'):
                        vulnerabilities.append({
                            'type': 'WEAK_SIGNATURE_ALGORITHM',
                            'severity': 'MEDIUM',
                            'description': 'Certificado usa algoritmo SHA1 (débil)',
                            'location': f'{hostname}:{port}',
                            'recommendation': 'Usar certificado con SHA-256 o superior'
                        })
                        
        except socket.timeout:
            vulnerabilities.append({
                'type': 'SSL_CONNECTION_TIMEOUT',
                'severity': 'MEDIUM',
                'description': 'Timeout al conectar por SSL',
                'location': f'{hostname}:{port}',
                'recommendation': 'Verificar configuración del servidor SSL'
            })
        except ssl.SSLError as e:
            vulnerabilities.append({
                'type': 'SSL_ERROR',
                'severity': 'HIGH',
                'description': f'Error SSL: {str(e)}',
                'location': f'{hostname}:{port}',
                'recommendation': 'Revisar configuración SSL del servidor'
            })
        
        return {'vulnerabilities': vulnerabilities}

    def _check_ssl_configuration(self, hostname: str, port: int) -> Dict:
        """Verifica configuración SSL avanzada"""
        vulnerabilities = []
        
        try:
            # Verificar protocolos soportados
            for protocol in self.weak_protocols:
                if self._test_protocol(hostname, port, protocol):
                    vulnerabilities.append({
                        'type': 'WEAK_SSL_PROTOCOL',
                        'severity': 'HIGH',
                        'description': f'Servidor soporta protocolo débil: {protocol}',
                        'location': f'{hostname}:{port}',
                        'recommendation': f'Deshabilitar {protocol} y usar solo TLS 1.2+'
                    })
            
        except Exception as e:
            # No agregar vulnerabilidad por errores en pruebas avanzadas
            pass
            
        return {'vulnerabilities': vulnerabilities}

    def _test_protocol(self, hostname: str, port: int, protocol: str) -> bool:
        """Prueba si un protocolo específico está habilitado"""
        try:
            protocol_map = {
                'SSLv2': None,
                'SSLv3': getattr(ssl.TLSVersion, 'SSLv3', None),
                'TLSv1': ssl.TLSVersion.TLSv1,
                'TLSv1.1': ssl.TLSVersion.TLSv1_1,
                'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            }
            
            version = protocol_map.get(protocol)
            if version is None:
                return False

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    return True
                    
        except:
            return False

    def _check_http_redirect(self, parsed_url) -> Dict:
        """Verifica si HTTP redirige a HTTPS"""
        vulnerabilities = []
        
        try:
            http_url = f"http://{parsed_url.netloc}{parsed_url.path}"
            response = requests.get(http_url, timeout=10, allow_redirects=False)
            
            if response.status_code not in [301, 302, 307, 308]:
                vulnerabilities.append({
                    'type': 'NO_HTTP_TO_HTTPS_REDIRECT',
                    'severity': 'MEDIUM',
                    'description': 'HTTP no redirige automáticamente a HTTPS',
                    'location': http_url,
                    'recommendation': 'Configurar redirección automática de HTTP a HTTPS'
                })
            else:
                location = response.headers.get('Location', '')
                if not location.startswith('https://'):
                    vulnerabilities.append({
                        'type': 'WEAK_HTTP_REDIRECT',
                        'severity': 'MEDIUM',
                        'description': 'Redirección HTTP no va a HTTPS',
                        'location': http_url,
                        'recommendation': 'Configurar redirección HTTP para que vaya a HTTPS'
                    })
                    
        except requests.RequestException:
            # No es crítico si HTTP no responde
            pass
            
        return {'vulnerabilities': vulnerabilities}

    def _verify_hostname(self, cert: Dict, hostname: str) -> bool:
        """Verifica si el certificado es válido para el hostname"""
        try:
            # Verificar subject
            subject = dict(x[0] for x in cert['subject'])
            if subject.get('commonName') == hostname:
                return True
            
            # Verificar Subject Alternative Names
            san = cert.get('subjectAltName', [])
            for name_type, name_value in san:
                if name_type == 'DNS' and name_value == hostname:
                    return True
                # Verificar wildcards
                if name_type == 'DNS' and name_value.startswith('*.'):
                    domain = name_value[2:]
                    if hostname.endswith(domain) and hostname.count('.') == domain.count('.') + 1:
                        return True
            
            return False
        except:
            return False

    def _build_result(self, url: str, scan_time: float, vulnerabilities: List) -> Dict:
        """Construye el resultado final del escaneo"""
        return {
            'scanner_type': self.name,
            'url': url,
            'scan_duration': round(scan_time, 2),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'status': 'VULNERABLE' if vulnerabilities else 'SECURE',
            'timestamp': datetime.now().isoformat()
        }

        # AGREGAR AL FINAL DE ssl_scanner.py

if __name__ == "__main__":
    import sys
    
    # URL de prueba por defecto
    test_url = "https://httpbin.org"
    
    # Usar URL del argumento si se proporciona
    if len(sys.argv) > 1:
        test_url = sys.argv[1]
    
    print(f"🔒 Iniciando escaneo SSL/TLS de: {test_url}")
    
    try:
        scanner = SSLScanner()
        result = scanner.scan(test_url)
        
        print(f"\n🔍 SSL/TLS Scan Summary")
        print(f"📋 URL: {result['url']}")
        print(f"⏱️  Duración: {result['scan_duration']}s")
        print(f"📊 Estado: {result['status']}")
        print(f"⚠️  Vulnerabilidades: {result['vulnerabilities_found']}")
        print(f"📅 Fecha: {result['timestamp']}")
        
        if result['vulnerabilities_found'] > 0:
            print(f"\n📋 VULNERABILIDADES ENCONTRADAS:")
            for i, vuln in enumerate(result['vulnerabilities'], 1):
                severity_icon = {
                    'CRITICAL': '💀',
                    'HIGH': '🚨',
                    'MEDIUM': '⚠️',
                    'LOW': 'ℹ️'
                }.get(vuln['severity'], '❓')
                
                print(f"{i}. {severity_icon} [{vuln['severity']}] {vuln['description']}")
            
            print(f"\n📄 Detalles completos:")
            for vuln in result['vulnerabilities']:
                print(f"{vuln['description']}")
                if vuln.get('details'):
                    print(f"   Detalles: {vuln['details']}")
                print(f"   Recomendación: {vuln['recommendation']}")
        else:
            print(f"\n✅ ¡Configuración SSL/TLS segura!")
            
    except Exception as e:
        print(f"❌ Error durante el escaneo: {e}")
        sys.exit(1)
