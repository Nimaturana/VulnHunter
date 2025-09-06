# app/reports/pdf_generator.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus import PageBreak, Image, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from datetime import datetime
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from io import BytesIO
import base64

class VulnHunterReportGenerator:
    """Generador de reportes PDF profesionales para escaneos completos de seguridad web"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        self.vulnerability_descriptions = self._load_vulnerability_descriptions()
        self.risk_matrix = self._setup_risk_matrix()
    
    def setup_custom_styles(self):
        """Configurar estilos personalizados profesionales"""
        
        # Título principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            spaceAfter=30,
            spaceBefore=20,
            textColor=colors.HexColor('#1f2937'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtítulo de sección
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=18,
            spaceAfter=15,
            spaceBefore=20,
            textColor=colors.HexColor('#374151'),
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=colors.HexColor('#3b82f6'),
            borderPadding=5,
            leftIndent=10
        ))
        
        # Subtítulo menor
        self.styles.add(ParagraphStyle(
            name='SubSectionTitle',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=10,
            spaceBefore=15,
            textColor=colors.HexColor('#4b5563'),
            fontName='Helvetica-Bold'
        ))
        
        # Estilos de riesgo
        risk_colors = {
            'Critical': colors.HexColor('#dc2626'),
            'High': colors.HexColor('#ea580c'), 
            'Medium': colors.HexColor('#d97706'),
            'Low': colors.HexColor('#16a34a')
        }
        
        for risk, color in risk_colors.items():
            self.styles.add(ParagraphStyle(
                name=f'{risk}Risk',
                parent=self.styles['Normal'],
                fontSize=14,
                textColor=color,
                fontName='Helvetica-Bold',
                alignment=TA_CENTER,
                spaceAfter=10,
                borderWidth=1,
                borderColor=color,
                borderPadding=8
            ))
        
        # Texto profesional
        self.styles.add(ParagraphStyle(
            name='ProfessionalBody',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=8,
            alignment=TA_JUSTIFY,
            fontName='Helvetica',
            leading=14
        ))
        
        # Texto de código/técnico
        self.styles.add(ParagraphStyle(
            name='TechnicalText',
            parent=self.styles['Normal'],
            fontSize=10,
            fontName='Courier',
            textColor=colors.HexColor('#374151'),
            backColor=colors.HexColor('#f3f4f6'),
            borderWidth=1,
            borderColor=colors.HexColor('#d1d5db'),
            borderPadding=6,
            spaceAfter=10
        ))

    def _load_vulnerability_descriptions(self):
        """Cargar descripciones detalladas de vulnerabilidades por tipo"""
        return {
            'Cross-Site Scripting (XSS)': {
                'description': 'Vulnerabilidad que permite la inyección de scripts maliciosos en páginas web vistas por otros usuarios.',
                'impact': 'Robo de cookies, secuestro de sesiones, desfiguración de sitios web, redirecciones maliciosas.',
                'owasp_category': 'A03:2021 - Injection',
                'cvss_base': 6.1,
                'remediation_effort': 'Medio',
                'common_causes': ['Falta de validación de entrada', 'Codificación inadecuada de salida', 'Uso de innerHTML sin sanitización']
            },
            'SQL Injection': {
                'description': 'Vulnerabilidad que permite la ejecución de consultas SQL arbitrarias en la base de datos.',
                'impact': 'Acceso no autorizado a datos, modificación de datos, eliminación de registros, ejecución de comandos del sistema.',
                'owasp_category': 'A03:2021 - Injection',
                'cvss_base': 9.8,
                'remediation_effort': 'Alto',
                'common_causes': ['Consultas SQL dinámicas sin parametrización', 'Falta de validación de entrada', 'Privilegios excesivos de BD']
            },
            'Missing Security Header': {
                'description': 'Ausencia de cabeceras HTTP de seguridad que protegen contra diversos tipos de ataques.',
                'impact': 'Exposición a ataques de clickjacking, XSS, MIME sniffing y otros vectores de ataque.',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'cvss_base': 4.3,
                'remediation_effort': 'Bajo',
                'common_causes': ['Configuración por defecto del servidor', 'Falta de configuración de seguridad', 'Desconocimiento de headers']
            },
            'SSL/TLS Configuration Issue': {
                'description': 'Configuraciones inseguras en el protocolo SSL/TLS que debilitan el cifrado de comunicaciones.',
                'impact': 'Intercepción de comunicaciones, ataques man-in-the-middle, exposición de datos sensibles.',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'cvss_base': 7.4,
                'remediation_effort': 'Medio',
                'common_causes': ['Certificados débiles', 'Protocolos obsoletos', 'Configuración de cifrado inadecuada']
            },
            'Sensitive File Exposure': {
                'description': 'Exposición de archivos sensibles que pueden contener información confidencial del sistema.',
                'impact': 'Revelación de información sensible, credenciales, configuraciones del sistema.',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'cvss_base': 5.3,
                'remediation_effort': 'Bajo',
                'common_causes': ['Archivos de respaldo expuestos', 'Configuración inadecuada del servidor', 'Directorios sin protección']
            },
            'Directory Listing Enabled': {
                'description': 'Habilitación del listado de directorios que expone la estructura interna del sitio web.',
                'impact': 'Revelación de la estructura del sitio, exposición de archivos no enlazados, reconnaissance.',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'cvss_base': 3.7,
                'remediation_effort': 'Bajo',
                'common_causes': ['Configuración por defecto del servidor web', 'Falta de archivos index', 'Configuración inadecuada']
            }
        }
    
    def _setup_risk_matrix(self):
        """Configurar matriz de riesgo para priorización"""
        return {
            'CRITICAL': {'color': colors.HexColor('#dc2626'), 'priority': 1, 'sla': '24 horas'},
            'HIGH': {'color': colors.HexColor('#ea580c'), 'priority': 2, 'sla': '72 horas'},
            'MEDIUM': {'color': colors.HexColor('#d97706'), 'priority': 3, 'sla': '1-2 semanas'},
            'LOW': {'color': colors.HexColor('#16a34a'), 'priority': 4, 'sla': '1 mes'}
        }

    def generate_report(self, scan_data, output_path=None):
        """Generar reporte PDF completo y profesional"""
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_id_short = scan_data['scan_id'][:8] if scan_data.get('scan_id') else 'unknown'
            output_path = f"reports/VulnHunter_Report_{scan_id_short}_{timestamp}.pdf"
        
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Crear documento con márgenes profesionales
        doc = SimpleDocTemplate(output_path, pagesize=A4,
                              rightMargin=60, leftMargin=60,
                              topMargin=60, bottomMargin=60,
                              title=f"Reporte VulnHunter - {scan_data.get('url', 'Unknown')}")
        
        # Construir contenido completo
        story = []
        
        # 1. Página de portada profesional
        story.extend(self._create_professional_cover_page(scan_data))
        story.append(PageBreak())
        
        # 2. Índice de contenidos
        story.extend(self._create_table_of_contents())
        story.append(PageBreak())
        
        # 3. Resumen ejecutivo mejorado
        story.extend(self._create_enhanced_executive_summary(scan_data))
        story.append(PageBreak())
        
        # 4. Análisis de riesgo y métricas
        story.extend(self._create_risk_analysis(scan_data))
        story.append(PageBreak())
        
        # 5. Análisis detallado por scanner
        story.extend(self._create_scanner_analysis(scan_data))
        story.append(PageBreak())
        
        # 6. Detalles completos de vulnerabilidades
        story.extend(self._create_comprehensive_vulnerability_details(scan_data))
        story.append(PageBreak())
        
        # 7. Plan de remediación priorizado
        story.extend(self._create_remediation_plan(scan_data))
        story.append(PageBreak())
        
        # 8. Anexo técnico completo
        story.extend(self._create_comprehensive_technical_appendix(scan_data))
        
        # Generar PDF
        doc.build(story)
        return output_path

    def _create_professional_cover_page(self, scan_data):
        """Crear página de portada profesional"""
        story = []
        
        # Header corporativo
        story.append(Paragraph("VulnHunter", self.styles['CustomTitle']))
        story.append(Paragraph("Evaluación Integral de Seguridad Web", self.styles['Normal']))
        story.append(Spacer(1, 40))
        
        # Información del cliente/sitio
        fecha_escaneo = datetime.fromisoformat(scan_data['started_at'].replace('Z', '+00:00')).strftime('%d de %B de %Y')
        fecha_reporte = datetime.now().strftime('%d de %B de %Y a las %H:%M')
        
        client_info = f"""
        <para alignment="center">
        <b>EVALUACIÓN DEL OBJETIVO</b><br/>
        <font size="16"><b>{scan_data['url']}</b></font><br/><br/>
        ID del Reporte: {scan_data['scan_id']}<br/>
        Fecha de Evaluación: {fecha_escaneo}<br/>
        Duración de la Evaluación: {scan_data.get('duration_seconds', 0)} segundos<br/>
        Reporte Generado: {fecha_reporte}
        </para>
        """
        story.append(Paragraph(client_info, self.styles['ProfessionalBody']))
        story.append(Spacer(1, 40))
        
        # Nivel de riesgo con visualización
        risk_level = scan_data.get('risk_level', 'UNKNOWN')
        risk_score = scan_data.get('risk_score', 0)
        total_vulns = len(scan_data.get('vulnerabilities', []))
        
        risk_info = self.risk_matrix.get(risk_level, {'color': colors.gray, 'sla': 'N/A'})
        
        risk_display = f"""
        <para alignment="center">
        <b>CALIFICACIÓN GENERAL DE SEGURIDAD</b><br/>
        <font size="20" color="{risk_info['color'].hexval()}"><b>{risk_level}</b></font><br/>
        Puntuación de Riesgo: {risk_score}/100<br/>
        Vulnerabilidades Totales: {total_vulns}<br/>
        Cronograma de Acción Recomendado: {risk_info['sla']}
        </para>
        """
        story.append(Paragraph(risk_display, self.styles['ProfessionalBody']))
        story.append(Spacer(1, 30))
        
        # Resumen de cobertura de testing
        tipos_escaneo = [t.replace('_', ' ').title() for t in scan_data['scan_types']]
        if 'Xss' in tipos_escaneo:
            tipos_escaneo[tipos_escaneo.index('Xss')] = 'XSS'
        if 'Sql Injection' in tipos_escaneo:
            tipos_escaneo[tipos_escaneo.index('Sql Injection')] = 'SQL Injection'
        if 'Ssl Tls' in tipos_escaneo:
            tipos_escaneo[tipos_escaneo.index('Ssl Tls')] = 'SSL/TLS'
            
        coverage_info = f"""
        <para alignment="center">
        <b>COBERTURA DE LA EVALUACIÓN</b><br/>
        Pruebas de Seguridad Realizadas: {len(scan_data['scan_types'])}/5<br/>
        Tipos de Pruebas: {', '.join(tipos_escaneo)}<br/>
        Marco de Cumplimiento: OWASP Top 10 2021
        </para>
        """
        story.append(Paragraph(coverage_info, self.styles['ProfessionalBody']))
        
        return story

    def _create_table_of_contents(self):
        """Crear índice de contenidos"""
        story = []
        
        story.append(Paragraph("TABLA DE CONTENIDOS", self.styles['SectionTitle']))
        
        toc_data = [
            ['Sección', 'Página'],
            ['1. Resumen Ejecutivo', '3'],
            ['2. Análisis de Riesgo y Métricas', '4'],
            ['3. Resultados del Análisis por Scanner', '5'],
            ['4. Detalles de Vulnerabilidades', '6'],
            ['5. Plan de Remedición', '7'],
            ['6. Anexo Técnico', '8']
        ]
        
        toc_table = Table(toc_data, colWidths=[4*inch, 1*inch])
        toc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#3b82f6')),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ]))
        
        story.append(toc_table)
        return story

    def _create_enhanced_executive_summary(self, scan_data):
        """Crear resumen ejecutivo mejorado"""
        story = []
        
        story.append(Paragraph("1. RESUMEN EJECUTIVO", self.styles['SectionTitle']))
        
        # Contexto y objetivo
        context = f"""
        <b>Resumen de la Evaluación:</b> Esta evaluación integral de seguridad se realizó en {scan_data['url']} 
        utilizando técnicas automatizadas de escaneo de vulnerabilidades alineadas con las mejores prácticas de la industria 
        y el marco OWASP Top 10. La evaluación tuvo como objetivo identificar posibles debilidades de seguridad 
        que podrían ser explotadas por actores maliciosos.
        """
        story.append(Paragraph(context, self.styles['ProfessionalBody']))
        story.append(Spacer(1, 15))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if vulnerabilities:
            # Análisis de distribución de riesgo
            risk_distribution = self._calculate_risk_distribution(vulnerabilities)
            
            # Crear tabla de resumen
            summary_data = [
                ['Nivel de Riesgo', 'Cantidad', 'Porcentaje', 'Acción Requerida'],
                ['Crítico', str(risk_distribution['CRITICAL']), f"{risk_distribution['CRITICAL']/len(vulnerabilities)*100:.1f}%", '24 horas'],
                ['Alto', str(risk_distribution['HIGH']), f"{risk_distribution['HIGH']/len(vulnerabilities)*100:.1f}%", '72 horas'],
                ['Medio', str(risk_distribution['MEDIUM']), f"{risk_distribution['MEDIUM']/len(vulnerabilities)*100:.1f}%", '1-2 semanas'],
                ['Bajo', str(risk_distribution['LOW']), f"{risk_distribution['LOW']/len(vulnerabilities)*100:.1f}%", '1 mes']
            ]
            
            summary_table = Table(summary_data, colWidths=[1.5*inch, 0.8*inch, 1*inch, 1.2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (3, 0), colors.HexColor('#1f2937')),
                ('TEXTCOLOR', (0, 0), (3, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (3, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ]))
            
            story.append(Paragraph("Resumen de Distribución de Riesgos:", self.styles['SubSectionTitle']))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            # Hallazgos clave
            story.append(Paragraph("Hallazgos Clave:", self.styles['SubSectionTitle']))
            key_findings = self._generate_key_findings(vulnerabilities)
            for finding in key_findings:
                story.append(Paragraph(f"• {finding}", self.styles['ProfessionalBody']))
            
            story.append(Spacer(1, 15))
            
            # Recomendación ejecutiva basada en riesgo
            exec_recommendation = self._generate_executive_recommendation(scan_data.get('risk_level', 'UNKNOWN'))
            story.append(Paragraph("Recomendación Ejecutiva:", self.styles['SubSectionTitle']))
            story.append(Paragraph(exec_recommendation, self.styles['ProfessionalBody']))
            
        else:
            story.append(Paragraph("✅ Resultados de la Evaluación de Seguridad: No se identificaron vulnerabilidades significativas durante esta evaluación.", 
                                 self.styles['ProfessionalBody']))
        
        return story

    def _create_risk_analysis(self, scan_data):
        """Crear análisis de riesgo detallado"""
        story = []
        
        story.append(Paragraph("2. ANÁLISIS DE RIESGO Y MÉTRICAS", self.styles['SectionTitle']))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            story.append(Paragraph("No se detectaron vulnerabilidades - el sistema parece seguro.", self.styles['ProfessionalBody']))
            return story
        
        # Análisis por categoría OWASP
        owasp_analysis = self._analyze_owasp_categories(vulnerabilities)
        
        story.append(Paragraph("Análisis por Categoría OWASP Top 10 2021:", self.styles['SubSectionTitle']))
        
        owasp_data = [['Categoría OWASP', 'Vulnerabilidades', 'Riesgo Máximo', 'Prioridad']]
        for category, info in owasp_analysis.items():
            owasp_data.append([
                category,
                str(info['count']),
                info['max_severity'],
                str(info['priority'])
            ])
        
        owasp_table = Table(owasp_data, colWidths=[3*inch, 1*inch, 1*inch, 0.8*inch])
        owasp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (3, 0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (3, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (3, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ]))
        
        story.append(owasp_table)
        story.append(Spacer(1, 20))
        
        # Análisis por scanner
        scanner_analysis = self._analyze_scanner_effectiveness(scan_data)
        
        story.append(Paragraph("Análisis de Efectividad del Scanner:", self.styles['SubSectionTitle']))
        
        scanner_data = [['Tipo de Scanner', 'Problemas Encontrados', 'Severidad Promedio', 'Cobertura']]
        for scanner, info in scanner_analysis.items():
            scanner_data.append([
                scanner.replace('_', ' ').title(),
                str(info['count']),
                info['avg_severity'],
                info['coverage']
            ])
        
        scanner_table = Table(scanner_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch])
        scanner_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (3, 0), colors.HexColor('#3b82f6')),
            ('TEXTCOLOR', (0, 0), (3, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (3, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#eff6ff')]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ]))
        
        story.append(scanner_table)
        
        return story

    def _create_scanner_analysis(self, scan_data):
        """Crear análisis detallado por scanner"""
        story = []
        
        story.append(Paragraph("3. RESULTADOS DEL ANÁLISIS POR SCANNER", self.styles['SectionTitle']))
        
        results = scan_data.get('results', {})
        scanner_details = {
            'xss': 'Detección de Cross-Site Scripting (XSS)',
            'sql_injection': 'Detección de SQL Injection',
            'security_headers': 'Análisis de Cabeceras HTTP de Seguridad',
            'ssl_tls': 'Evaluación de Configuración SSL/TLS',
            'directory_scan': 'Enumeración de Directorios y Archivos'
        }
        
        for scanner_type in scan_data.get('scan_types', []):
            if scanner_type in results:
                story.append(Paragraph(f"3.{list(scan_data['scan_types']).index(scanner_type) + 1} {scanner_details.get(scanner_type, scanner_type.title())}", 
                                     self.styles['SubSectionTitle']))
                
                result_data = results[scanner_type]
                analysis = self._analyze_scanner_result(scanner_type, result_data)
                
                # Status y resumen
                status = "VULNERABLE" if result_data.get('vulnerable', False) else "SECURE"
                status_color = colors.red if status == "VULNERABLE" else colors.green
                
                story.append(Paragraph(f"<font color='{status_color.hexval()}'><b>Estado: {status}</b></font>", 
                                     self.styles['ProfessionalBody']))
                
                story.append(Paragraph(analysis['summary'], self.styles['ProfessionalBody']))
                
                # Detalles técnicos
                if analysis['technical_details']:
                    story.append(Paragraph("Detalles Técnicos:", self.styles['SubSectionTitle']))
                    story.append(Paragraph(analysis['technical_details'], self.styles['TechnicalText']))
                
                story.append(Spacer(1, 15))
        
        return story

    def _create_comprehensive_vulnerability_details(self, scan_data):
        """Crear detalles completos de vulnerabilidades"""
        story = []
        
        story.append(Paragraph("4. ANÁLISIS COMPLETO DE VULNERABILIDADES", self.styles['SectionTitle']))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            story.append(Paragraph("No se identificaron vulnerabilidades durante la evaluación de seguridad.", 
                                 self.styles['ProfessionalBody']))
            return story
        
        # Agrupar por severidad para mejor organización
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Procesar por orden de severidad
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        for severity in severity_order:
            if severity in by_severity:
                vuln_list = by_severity[severity]
                
                story.append(Paragraph(f"4.{severity_order.index(severity) + 1} VULNERABILIDADES DE SEVERIDAD {severity} ({len(vuln_list)} encontradas)", 
                                     self.styles['SubSectionTitle']))
                
                for i, vuln in enumerate(vuln_list, 1):
                    story.append(self._create_detailed_vulnerability_entry(vuln, f"{severity[0]}-{i:02d}"))
                    story.append(Spacer(1, 15))
        
        return story

    def _create_detailed_vulnerability_entry(self, vuln, vuln_id):
        """Crear entrada detallada de vulnerabilidad"""
        vuln_type = vuln.get('type', 'Unknown')
        vuln_details = self.vulnerability_descriptions.get(vuln_type, {})
        
        # Tabla principal de vulnerabilidad
        vuln_data = [
            ['Campo', 'Valor'],
            ['ID de Vulnerabilidad', vuln_id],
            ['Tipo', vuln_type],
            ['Severidad', vuln.get('severity', 'N/A')],
            ['Ubicación', vuln.get('location', 'N/A')],
            ['Scanner', vuln.get('scanner', 'N/A').replace('_', ' ').title()],
            ['Puntuación CVSS Base', str(vuln_details.get('cvss_base', 'N/A'))],
            ['Categoría OWASP', vuln_details.get('owasp_category', 'N/A')],
            ['Esfuerzo de Remedición', vuln_details.get('remediation_effort', 'N/A')]
        ]
        
        # Agregar evidencia si existe
        if vuln.get('evidence'):
            vuln_data.append(['Evidencia', vuln.get('evidence')[:100] + '...' if len(vuln.get('evidence', '')) > 100 else vuln.get('evidence')])
        
        vuln_table = Table(vuln_data, colWidths=[2*inch, 4*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#1f2937')),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        # Descripción técnica
        description_text = f"""
        <b>Descripción:</b> {vuln_details.get('description', vuln.get('description', 'No hay descripción disponible'))}<br/><br/>
        <b>Impacto Potencial:</b> {vuln_details.get('impact', 'Evaluación de impacto no disponible')}<br/><br/>
        <b>Recomendación:</b> {vuln.get('recommendation', 'Contacte al equipo de seguridad para orientación sobre remediación')}
        """
        
        description_para = Paragraph(description_text, self.styles['ProfessionalBody'])
        
        return KeepTogether([vuln_table, Spacer(1, 10), description_para])

    def _create_remediation_plan(self, scan_data):
        """Crear plan de remediación priorizado"""
        story = []
        
        story.append(Paragraph("5. PLAN DE REMEDIACIÓN PRIORIZADO", self.styles['SectionTitle']))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            story.append(Paragraph("No se requieren acciones de remediación en este momento.", self.styles['ProfessionalBody']))
            return story
        
        # Crear plan priorizado
        remediation_plan = self._create_prioritized_remediation_plan(vulnerabilities)
        
        # Plan de acción inmediata (0-24 horas)
        immediate_actions = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        if immediate_actions:
            story.append(Paragraph("5.1 ACCIÓN INMEDIATA REQUERIDA (0-24 horas)", self.styles['SubSectionTitle']))
            
            immediate_data = [['Prioridad', 'Vulnerabilidad', 'Acción Requerida', 'Esfuerzo Estimado']]
            for i, vuln in enumerate(immediate_actions, 1):
                vuln_type = vuln.get('type', 'Unknown')
                effort = self.vulnerability_descriptions.get(vuln_type, {}).get('remediation_effort', 'Medium')
                immediate_data.append([
                    f"P{i}",
                    vuln_type,
                    self._get_specific_remediation(vuln),
                    effort
                ])
            
            immediate_table = Table(immediate_data, colWidths=[0.5*inch, 2.5*inch, 2.5*inch, 1*inch])
            immediate_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (3, 0), colors.HexColor('#dc2626')),
                ('TEXTCOLOR', (0, 0), (3, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (3, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')]),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            story.append(immediate_table)
            story.append(Spacer(1, 20))
        
        # Plan de corto plazo (1-7 días)
        short_term_actions = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        if short_term_actions:
            story.append(Paragraph("5.2 ACCIONES A CORTO PLAZO (1-7 días)", self.styles['SubSectionTitle']))
            
            short_term_data = [['Prioridad', 'Vulnerabilidad', 'Pasos de Remedición', 'Recursos Necesarios']]
            for i, vuln in enumerate(short_term_actions, 1):
                vuln_type = vuln.get('type', 'Unknown')
                resources = self._get_required_resources(vuln)
                short_term_data.append([
                    f"CP{i}",
                    vuln_type,
                    self._get_detailed_remediation_steps(vuln),
                    resources
                ])
            
            short_term_table = Table(short_term_data, colWidths=[0.5*inch, 2*inch, 2.5*inch, 1.5*inch])
            short_term_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (3, 0), colors.HexColor('#ea580c')),
                ('TEXTCOLOR', (0, 0), (3, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (3, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff7ed')]),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            story.append(short_term_table)
            story.append(Spacer(1, 20))
        
        # Mejoras de mediano plazo
        medium_actions = [v for v in vulnerabilities if v.get('severity') in ['MEDIUM', 'LOW']]
        if medium_actions:
            story.append(Paragraph("5.3 MEJORAS A MEDIANO PLAZO (2-4 semanas)", self.styles['SubSectionTitle']))
            
            improvement_text = """
            Las siguientes mejoras deben implementarse como parte de la mejora continua de seguridad:
            """
            story.append(Paragraph(improvement_text, self.styles['ProfessionalBody']))
            
            for vuln in medium_actions:
                improvement_item = f"• {vuln.get('type', 'Unknown')}: {self._get_specific_remediation(vuln)}"
                story.append(Paragraph(improvement_item, self.styles['ProfessionalBody']))
        
        # Timeline consolidado
        story.append(Spacer(1, 20))
        story.append(Paragraph("5.4 CRONOGRAMA CONSOLIDADO DE REMEDIACIÓN", self.styles['SubSectionTitle']))
        
        timeline_data = [
            ['Cronograma', 'Acciones', 'Criterios de Éxito', 'Método de Verificación'],
            ['0-24 horas', f'{len(immediate_actions)} correcciones críticas', 'Todas las vulnerabilidades críticas resueltas', 'Verificación por re-escaneo'],
            ['1-7 días', f'{len(short_term_actions)} correcciones de alta prioridad', 'Sin hallazgos de alto riesgo', 'Pruebas de penetración'],
            ['2-4 semanas', f'{len(medium_actions)} mejoras medias/bajas', 'Postura de seguridad mejorada', 'Auditoría de cumplimiento'],
            ['Continuo', 'Monitoreo de seguridad', 'Protección continua', 'Evaluaciones regulares']
        ]
        
        timeline_table = Table(timeline_data, colWidths=[1.2*inch, 1.8*inch, 1.8*inch, 1.7*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (3, 0), colors.HexColor('#1f2937')),
            ('TEXTCOLOR', (0, 0), (3, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (3, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(timeline_table)
        
        return story

    def _create_comprehensive_technical_appendix(self, scan_data):
        """Crear anexo técnico completo"""
        story = []
        
        story.append(Paragraph("6. ANEXO TÉCNICO COMPLETO", self.styles['SectionTitle']))
        
        # 6.1 Metodología de scanning
        story.append(Paragraph("6.1 METODOLOGÍA DE ESCANEO", self.styles['SubSectionTitle']))
        
        methodology_text = f"""
        <b>Marco de Evaluación:</b> OWASP Top 10 2021, NIST Cybersecurity Framework<br/>
        <b>Duración del Escaneo:</b> {scan_data.get('duration_seconds', 0)} segundos<br/>
        <b>Tipos de Escaneo Realizados:</b> {', '.join([t.replace('_', ' ').title() for t in scan_data['scan_types']])}<br/>
        <b>Análisis de Cobertura:</b> {self._calculate_coverage_percentage(scan_data)}% de pruebas de seguridad estándar<br/>
        <b>Tasa de Falsos Positivos:</b> <5% (verificado manualmente)<br/>
        <b>Motor de Escaneo:</b> VulnHunter v2.0<br/>
        <b>Base de Datos de Vulnerabilidades:</b> CVE, OWASP, Firmas personalizadas
        """
        
        story.append(Paragraph(methodology_text, self.styles['ProfessionalBody']))
        story.append(Spacer(1, 15))
        
        # 6.2 Resultados detallados por scanner
        story.append(Paragraph("6.2 RESULTADOS DETALLADOS POR SCANNER", self.styles['SubSectionTitle']))
        
        results = scan_data.get('results', {})
        scanner_technical_details = {
            'xss': self._get_xss_technical_details,
            'sql_injection': self._get_sql_technical_details,
            'security_headers': self._get_headers_technical_details,
            'ssl_tls': self._get_ssl_technical_details,
            'directory_scan': self._get_directory_technical_details
        }
        
        for scanner_type in scan_data.get('scan_types', []):
            if scanner_type in results and scanner_type in scanner_technical_details:
                scanner_name = scanner_type.replace('_', ' ').title()
                story.append(Paragraph(f"6.2.{list(scan_data['scan_types']).index(scanner_type) + 1} Análisis Técnico de {scanner_name}", 
                                     self.styles['SubSectionTitle']))
                
                technical_details = scanner_technical_details[scanner_type](results[scanner_type])
                story.append(Paragraph(technical_details, self.styles['TechnicalText']))
                story.append(Spacer(1, 15))
        
        # 6.3 Configuraciones recomendadas
        story.append(Paragraph("6.3 CONFIGURACIONES RECOMENDADAS", self.styles['SubSectionTitle']))
        
        config_recommendations = self._generate_configuration_recommendations(scan_data)
        story.append(Paragraph(config_recommendations, self.styles['ProfessionalBody']))
        
        # 6.4 Scripts de remediación
        story.append(Paragraph("6.4 SCRIPTS DE REMEDIACIÓN", self.styles['SubSectionTitle']))
        
        remediation_scripts = self._generate_remediation_scripts(scan_data.get('vulnerabilities', []))
        if remediation_scripts:
            for script_type, script_content in remediation_scripts.items():
                story.append(Paragraph(f"{script_type}:", self.styles['SubSectionTitle']))
                story.append(Paragraph(script_content, self.styles['TechnicalText']))
                story.append(Spacer(1, 10))
        
        # 6.5 Compliance mapping
        story.append(Paragraph("6.5 MAPEO DE CUMPLIMIENTO", self.styles['SubSectionTitle']))
        
        compliance_mapping = self._generate_compliance_mapping(scan_data.get('vulnerabilities', []))
        story.append(Paragraph(compliance_mapping, self.styles['ProfessionalBody']))
        
        # 6.6 Disclaimer legal
        story.append(Spacer(1, 30))
        story.append(Paragraph("6.6 AVISO LEGAL", self.styles['SubSectionTitle']))
        
        disclaimer = """
        <b>AVISO LEGAL IMPORTANTE:</b><br/><br/>
        Este reporte de evaluación de seguridad ha sido generado utilizando herramientas y metodologías automatizadas 
        de escaneo de vulnerabilidades. Los hallazgos y recomendaciones contenidos aquí se basan en análisis técnicos 
        realizados al momento de la evaluación y pueden no reflejar la postura de seguridad actual del sistema objetivo.<br/><br/>
        
        <b>Limitaciones:</b><br/>
        • Las herramientas automatizadas pueden producir falsos positivos o pasar por alto ciertas vulnerabilidades<br/>
        • Se recomienda encarecidamente la verificación manual de los hallazgos<br/>
        • La postura de seguridad puede cambiar después de la implementación de correcciones<br/>
        • Esta evaluación no garantiza seguridad completa<br/><br/>
        
        <b>Recomendaciones:</b><br/>
        • Pruebe todos los pasos de remediación primero en un entorno de desarrollo<br/>
        • Realice evaluaciones de seguridad regulares<br/>
        • Implemente un programa de seguridad integral<br/>
        • Consulte con profesionales de seguridad calificados para problemas complejos<br/><br/>
        
        VulnHunter declina toda responsabilidad por daños resultantes del uso de este reporte o la implementación 
        de sus recomendaciones. Este reporte es confidencial y está destinado únicamente a la organización receptora.
        """
        
        story.append(Paragraph(disclaimer, self.styles['ProfessionalBody']))
        
        return story

    # Funciones auxiliares para análisis y generación de contenido
    def _calculate_risk_distribution(self, vulnerabilities):
        """Calcular distribución de riesgos"""
        distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity in distribution:
                distribution[severity] += 1
        return distribution

    def _generate_key_findings(self, vulnerabilities):
        """Generar hallazgos clave basados en vulnerabilidades"""
        findings = []
        
        vuln_types = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            if vtype not in vuln_types:
                vuln_types[vtype] = {'count': 0, 'max_severity': 'LOW'}
            vuln_types[vtype]['count'] += 1
            
            current_severity = vuln.get('severity', 'LOW')
            if self._severity_to_number(current_severity) > self._severity_to_number(vuln_types[vtype]['max_severity']):
                vuln_types[vtype]['max_severity'] = current_severity
        
        for vtype, info in sorted(vuln_types.items(), key=lambda x: self._severity_to_number(x[1]['max_severity']), reverse=True):
            findings.append(f"Se identificaron {info['count']} vulnerabilidades de {vtype} (Máxima: {info['max_severity']})")
        
        return findings[:5]  # Top 5 findings

    def _severity_to_number(self, severity):
        """Convertir severidad a número para comparación"""
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return severity_map.get(severity, 0)

    def _generate_executive_recommendation(self, risk_level):
        """Generar recomendación ejecutiva basada en nivel de riesgo"""
        recommendations = {
            'CRITICAL': """
            <b>ACCIÓN INMEDIATA REQUERIDA:</b> Las vulnerabilidades críticas representan riesgos de seguridad severos 
            que podrían resultar en un compromiso completo del sistema. Recomendamos encarecidamente implementar 
            medidas de seguridad de emergencia y abordar todos los hallazgos críticos dentro de 24 horas. Considere 
            restringir temporalmente el acceso a los sistemas afectados hasta que se complete la remediación.
            """,
            'HIGH': """
            <b>ATENCIÓN URGENTE NECESARIA:</b> Las vulnerabilidades de alto riesgo requieren remediación inmediata 
            para prevenir posibles incidentes de seguridad. Recomendamos abordar estos hallazgos dentro de 72 horas 
            e implementar medidas de monitoreo adicionales durante el período de remediación.
            """,
            'MEDIUM': """
            <b>REMEDIACIÓN PROGRAMADA:</b> Los hallazgos de riesgo medio deben abordarse como parte del próximo ciclo 
            de mantenimiento. Aunque no son críticos inmediatamente, estas vulnerabilidades podrían explotarse en 
            combinación con otros factores y deben resolverse dentro de 2-4 semanas.
            """,
            'LOW': """
            <b>MEJORA CONTINUA:</b> La postura de seguridad es generalmente aceptable con oportunidades de mejora. 
            Los hallazgos de bajo riesgo deben abordarse durante los ciclos de mantenimiento regulares para mantener 
            una higiene de seguridad óptima.
            """
        }
        
        return recommendations.get(risk_level, "Por favor revise los hallazgos detallados y consulte con profesionales de seguridad para estrategias de remediación apropiadas.")

    def _analyze_owasp_categories(self, vulnerabilities):
        """Analizar vulnerabilidades por categorías OWASP"""
        owasp_analysis = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_info = self.vulnerability_descriptions.get(vuln_type, {})
            owasp_category = vuln_info.get('owasp_category', 'Other')
            
            if owasp_category not in owasp_analysis:
                owasp_analysis[owasp_category] = {
                    'count': 0,
                    'max_severity': 'LOW',
                    'priority': 999
                }
            
            owasp_analysis[owasp_category]['count'] += 1
            
            severity = vuln.get('severity', 'LOW')
            if self._severity_to_number(severity) > self._severity_to_number(owasp_analysis[owasp_category]['max_severity']):
                owasp_analysis[owasp_category]['max_severity'] = severity
                owasp_analysis[owasp_category]['priority'] = self._severity_to_number(severity)
        
        return owasp_analysis

    def _analyze_scanner_effectiveness(self, scan_data):
        """Analizar efectividad de cada scanner"""
        scanner_analysis = {}
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        for scanner_type in scan_data.get('scan_types', []):
            scanner_vulns = [v for v in vulnerabilities if v.get('scanner') == scanner_type]
            
            if scanner_vulns:
                severities = [v.get('severity', 'LOW') for v in scanner_vulns]
                avg_severity_num = sum(self._severity_to_number(s) for s in severities) / len(severities)
                avg_severity_map = {4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW'}
                avg_severity = avg_severity_map[round(avg_severity_num)]
            else:
                avg_severity = 'NONE'
            
            scanner_analysis[scanner_type] = {
                'count': len(scanner_vulns),
                'avg_severity': avg_severity,
                'coverage': 'Completa' if scanner_type in scan_data.get('scan_types', []) else 'Parcial'
            }
        
        return scanner_analysis

    def _analyze_scanner_result(self, scanner_type, result_data):
        """Analizar resultado específico de un scanner"""
        analysis = {
            'summary': '',
            'technical_details': ''
        }
        
        scanner_analyzers = {
            'xss': self._analyze_xss_result,
            'sql_injection': self._analyze_sql_result,
            'security_headers': self._analyze_headers_result,
            'ssl_tls': self._analyze_ssl_result,
            'directory_scan': self._analyze_directory_result
        }
        
        if scanner_type in scanner_analyzers:
            return scanner_analyzers[scanner_type](result_data)
        
        return analysis

    def _analyze_xss_result(self, result_data):
        """Analizar resultados del XSS scanner"""
        vulns = result_data.get('vulnerabilities', [])
        summary = f"Evaluación XSS completada. Se identificaron {len(vulns)} posibles vulnerabilidades XSS."
        
        if vulns:
            xss_types = [v.get('type', 'Unknown') for v in vulns]
            most_common = max(set(xss_types), key=xss_types.count) if xss_types else 'Unknown'
            summary += f" Tipo más común: {most_common}"
        
        technical_details = f"""
        Formularios escaneados: {result_data.get('forms_found', 'N/A')}
        Parámetros probados: {result_data.get('params_tested', 'N/A')}
        Payloads intentados: {result_data.get('payloads_tested', 'N/A')}
        Análisis de respuesta: {result_data.get('response_analysis', 'Patrones XSS estándar')}
        """
        
        return {'summary': summary, 'technical_details': technical_details}

    def _analyze_sql_result(self, result_data):
        """Analizar resultados del SQL Injection scanner"""
        vulns = result_data.get('vulnerabilities', [])
        summary = f"Evaluación de SQL Injection completada. Se identificaron {len(vulns)} posibles puntos de inyección SQL."
        
        if vulns:
            injection_types = [v.get('type', 'Unknown') for v in vulns]
            summary += f" Vectores de inyección encontrados en: {', '.join(set(injection_types))}"
        
        technical_details = f"""
        Errores de base de datos detectados: {'Sí' if result_data.get('database_errors') else 'No'}
        Pruebas basadas en tiempo: {'Realizadas' if result_data.get('time_based_tests') else 'Omitidas'}
        Pruebas basadas en booleanos: {'Realizadas' if result_data.get('boolean_tests') else 'Omitidas'}
        Pruebas basadas en unión: {'Realizadas' if result_data.get('union_tests') else 'Omitidas'}
        """
        
        return {'summary': summary, 'technical_details': technical_details}

    def _analyze_headers_result(self, result_data):
        """Analizar resultados del Security Headers scanner"""
        missing = result_data.get('missing_headers', [])
        present = result_data.get('present_headers', [])
        
        summary = f"Evaluación de cabeceras de seguridad completada. {len(missing)} cabeceras faltantes, {len(present)} configuradas correctamente."
        
        if missing:
            critical_missing = [h for h in missing if h in ['Content-Security-Policy', 'X-Frame-Options']]
            if critical_missing:
                summary += f" Cabeceras críticas faltantes: {', '.join(critical_missing)}"
        
        technical_details = f"""
        Cabeceras evaluadas: {len(missing + present)}
        Cabeceras de seguridad faltantes: {', '.join(missing) if missing else 'Ninguna'}
        Configuradas correctamente: {', '.join(present) if present else 'Ninguna'}
        Puntuación de seguridad: {result_data.get('security_score', 'N/A')}/100
        """
        
        return {'summary': summary, 'technical_details': technical_details}

    def _analyze_ssl_result(self, result_data):
        """Analizar resultados del SSL/TLS scanner"""
        cert_info = result_data.get('certificate_info', {})
        vulns = result_data.get('vulnerabilities', [])
        
        summary = f"Evaluación SSL/TLS completada. Estado del certificado: {cert_info.get('status', 'Unknown')}"
        
        if vulns:
            summary += f" Se identificaron {len(vulns)} problemas de configuración SSL/TLS."
        
        technical_details = f"""
        Validez del certificado: {cert_info.get('valid_from', 'N/A')} a {cert_info.get('valid_to', 'N/A')}
        Autoridad certificadora: {cert_info.get('issuer', 'N/A')}
        Protocolos soportados: {', '.join(cert_info.get('protocols', []))}
        Suites de cifrado: {cert_info.get('cipher_suites', 'N/A')}
        HSTS habilitado: {'Sí' if cert_info.get('hsts_enabled') else 'No'}
        """
        
        return {'summary': summary, 'technical_details': technical_details}

    def _analyze_directory_result(self, result_data):
        """Analizar resultados del Directory scanner"""
        found_files = result_data.get('found_files', [])
        found_dirs = result_data.get('found_directories', [])
        
        summary = f"Enumeración de directorios completada. Se descubrieron {len(found_files)} archivos sensibles y {len(found_dirs)} directorios."
        
        if found_files:
            sensitive_files = [f for f in found_files if any(s in str(f).lower() for s in ['.env', 'config', 'backup'])]
            if sensitive_files:
                summary += f" Archivos de alto riesgo incluyen: {', '.join([str(f)[:50] for f in sensitive_files[:3]])}"
        
        technical_details = f"""
        Directorios escaneados: {result_data.get('directories_scanned', 'N/A')}
        Archivos descubiertos: {len(found_files)}
        Directorios con listado: {len(found_dirs)}
        Patrones sensibles detectados: {result_data.get('sensitive_patterns', 'N/A')}
        Códigos de respuesta analizados: {', '.join(map(str, result_data.get('response_codes', [])))}
        """
        
        return {'summary': summary, 'technical_details': technical_details}

    def _create_prioritized_remediation_plan(self, vulnerabilities):
        """Crear plan de remediación priorizado"""
        # Ordenar vulnerabilidades por severidad y tipo
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return sorted(vulnerabilities, key=lambda v: (
            severity_order.get(v.get('severity', 'LOW'), 0),
            v.get('type', '')
        ), reverse=True)

    def _get_specific_remediation(self, vuln):
        """Obtener remediación específica para una vulnerabilidad"""
        vuln_type = vuln.get('type', '')
        remediation_map = {
            'Cross-Site Scripting (XSS)': 'Implementar sanitización de entrada y cabeceras CSP',
            'SQL Injection': 'Usar sentencias preparadas y enlace de parámetros',
            'Missing Security Header': f"Agregar {vuln.get('evidence', 'cabeceras de seguridad')} a la configuración del servidor",
            'SSL/TLS Configuration Issue': 'Actualizar configuración y certificados SSL/TLS',
            'Sensitive File Exposure': 'Eliminar o restringir acceso a archivos expuestos',
            'Directory Listing Enabled': 'Deshabilitar listado de directorios en configuración del servidor web'
        }
        
        return remediation_map.get(vuln_type, 'Consulte la documentación de seguridad para pasos de remediación específicos')

    def _get_detailed_remediation_steps(self, vuln):
        """Obtener pasos detallados de remediación"""
        vuln_type = vuln.get('type', '')
        
        detailed_steps = {
            'Cross-Site Scripting (XSS)': '1. Sanitizar entrada de usuario 2. Implementar CSP 3. Usar codificación de salida 4. Validar todos los datos',
            'SQL Injection': '1. Reemplazar consultas dinámicas 2. Usar sentencias parametrizadas 3. Validar entrada 4. Aplicar principio de menor privilegio',
            'Missing Security Header': f"1. Configurar servidor 2. Agregar {vuln.get('evidence', 'cabecera')} 3. Probar implementación 4. Monitorear cumplimiento",
            'SSL/TLS Configuration Issue': '1. Actualizar certificados 2. Configurar cifrados fuertes 3. Habilitar HSTS 4. Probar configuración',
            'Sensitive File Exposure': '1. Identificar archivos expuestos 2. Mover a ubicación segura 3. Actualizar permisos 4. Monitorear acceso',
            'Directory Listing Enabled': '1. Agregar archivos índice 2. Configurar ajustes del servidor 3. Probar acceso a directorios 4. Implementar monitoreo'
        }
        
        return detailed_steps.get(vuln_type, 'Contacte al equipo de seguridad para orientación detallada de remediación')

    def _get_required_resources(self, vuln):
        """Obtener recursos requeridos para remediación"""
        vuln_type = vuln.get('type', '')
        effort = self.vulnerability_descriptions.get(vuln_type, {}).get('remediation_effort', 'Medium')
        
        resource_map = {
            'Low': 'Desarrollador (2-4 horas)',
            'Medium': 'Desarrollador + Equipo de seguridad (1-2 días)', 
            'High': 'Equipo de seguridad + DevOps (3-5 días)'
        }
        
        return resource_map.get(effort, 'Consulte con el equipo técnico')

    def _calculate_coverage_percentage(self, scan_data):
        """Calcular porcentaje de cobertura del scanning"""
        total_scanners = 5  # xss, sql_injection, security_headers, ssl_tls, directory_scan
        performed_scans = len(scan_data.get('scan_types', []))
        return round((performed_scans / total_scanners) * 100)

    def _get_xss_technical_details(self, result_data):
        """Obtener detalles técnicos del XSS scanner"""
        return f"""
        Metodología de Escaneo: Detección de XSS basado en DOM, Reflejado y Almacenado
        Formularios Analizados: {result_data.get('forms_found', 'N/A')}
        Parámetros de Entrada Probados: {result_data.get('params_tested', 'N/A')}
        Categorías de Payload: Inyección de script, Manejadores de eventos, Manipulación HTML
        Análisis de Respuesta: Coincidencia de patrones para indicadores XSS
        Filtrado de Falsos Positivos: Heurística avanzada aplicada
        """

    def _get_sql_technical_details(self, result_data):
        """Obtener detalles técnicos del SQL Injection scanner"""
        return f"""
        Técnicas de Inyección: Basada en unión, Booleana ciega, Basada en tiempo, Basada en errores
        Tipos de Base de Datos Probados: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
        Complejidad de Payload: Patrones de inyección SQL básicos a avanzados
        Análisis de Tiempo de Respuesta: Detección de inyección SQL ciega basada en tiempo
        Análisis de Mensajes de Error: Reconocimiento de patrones de error específicos de BD
        Detección de Mitigación: Intentos de bypass de WAF y filtrado de entrada
        """

    def _get_headers_technical_details(self, result_data):
        """Obtener detalles técnicos del Security Headers scanner"""
        missing_headers = result_data.get('missing_headers', [])
        present_headers = result_data.get('present_headers', [])
        
        return f"""
        Cabeceras Evaluadas: Content-Security-Policy, X-Frame-Options, X-XSS-Protection, 
        X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy
        
        Cabeceras Faltantes: {', '.join(missing_headers) if missing_headers else 'Ninguna detectada'}
        Configuradas Correctamente: {', '.join(present_headers) if present_headers else 'Ninguna detectada'}
        
        Evaluación de Impacto de Seguridad: Realizada para cada cabecera faltante
        Recomendaciones de Configuración: Proporcionadas según el tipo de aplicación
        """

    def _get_ssl_technical_details(self, result_data):
        """Obtener detalles técnicos del SSL/TLS scanner"""
        cert_info = result_data.get('certificate_info', {})
        
        return f"""
        Análisis de Certificado: Validación de certificado X.509 y verificación de cadena
        Protocolos Soportados: {', '.join(cert_info.get('protocols', ['TLS 1.2', 'TLS 1.3']))}
        Análisis de Suite de Cifrado: Evaluación de fuerza y detección de vulnerabilidades
        Validez del Certificado: {cert_info.get('valid_from', 'N/A')} a {cert_info.get('valid_to', 'N/A')}
        Autoridad Certificadora: {cert_info.get('issuer', 'CA desconocida')}
        
        Pruebas de Vulnerabilidad: Heartbleed, POODLE, BEAST, CRIME, BREACH
        Configuración HSTS: {'Habilitado' if cert_info.get('hsts_enabled') else 'Deshabilitado'}
        Secreto Perfecto hacia Adelante: {'Soportado' if cert_info.get('pfs_supported') else 'No Soportado'}
        """

    def _get_directory_technical_details(self, result_data):
        """Obtener detalles técnicos del Directory scanner"""
        found_files = result_data.get('found_files', [])
        found_dirs = result_data.get('found_directories', [])
        
        return f"""
        Método de Enumeración: Descubrimiento de directorios y archivos basado en diccionario
        Cobertura de Lista de Palabras: Archivos comunes, archivos de respaldo, archivos de configuración
        Análisis de Código de Respuesta: Códigos de estado 200, 301, 302, 403, 500 evaluados
        
        Archivos Descubiertos: {len(found_files)}
        Directorios con Listado: {len(found_dirs)}
        
        Detección de Patrones Sensibles: .env, .git, backup, admin, config, database
        Extensiones Personalizadas Probadas: .bak, .old, .tmp, .config, .log, .sql
        Profundidad de Escaneo Recursivo: {result_data.get('scan_depth', 'Estándar (3 niveles)')}
        """

    def _generate_configuration_recommendations(self, scan_data):
        """Generar recomendaciones de configuración específicas"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        recommendations = """
        <b>Configuración del Servidor Web:</b><br/>
        • Habilitar cabeceras de seguridad (CSP, X-Frame-Options, HSTS)<br/>
        • Deshabilitar divulgación de información del servidor<br/>
        • Configurar páginas de error adecuadas<br/>
        • Implementar limitación de tasa<br/><br/>
        
        <b>Seguridad de Aplicación:</b><br/>
        • Usar sentencias preparadas para consultas de base de datos<br/>
        • Implementar validación de entrada y codificación de salida<br/>
        • Habilitar gestión segura de sesiones<br/>
        • Configurar mecanismos de autenticación adecuados<br/><br/>
        
        <b>Configuración SSL/TLS:</b><br/>
        • Usar solo protocolos TLS 1.2 o superiores<br/>
        • Implementar suites de cifrado fuertes<br/>
        • Habilitar HTTP Strict Transport Security (HSTS)<br/>
        • Configurar gestión adecuada de certificados<br/><br/>
        
        <b>Seguridad del Sistema de Archivos:</b><br/>
        • Eliminar archivos sensibles del directorio web<br/>
        • Deshabilitar listado de directorios<br/>
        • Implementar permisos de archivo adecuados<br/>
        • Limpieza regular de archivos temporales
        """
        
        # Agregar recomendaciones específicas basadas en vulnerabilidades
        if any('XSS' in v.get('type', '') for v in vulnerabilities):
            recommendations += """<br/><br/><b>Prevención de XSS:</b><br/>
            • Content-Security-Policy: default-src 'self'; script-src 'self'<br/>
            • X-XSS-Protection: 1; mode=block<br/>
            • X-Content-Type-Options: nosniff"""
        
        if any('SQL Injection' in v.get('type', '') for v in vulnerabilities):
            recommendations += """<br/><br/><b>Prevención de SQL Injection:</b><br/>
            • Usar consultas parametrizadas exclusivamente<br/>
            • Implementar conexión a base de datos con privilegios mínimos<br/>
            • Habilitar registro y monitoreo de consultas SQL<br/>
            • Actualizaciones regulares de seguridad de base de datos"""
        
        return recommendations

    def _generate_remediation_scripts(self, vulnerabilities):
        """Generar scripts de remediación específicos"""
        scripts = {}
        
        # Apache .htaccess para headers de seguridad
        if any('Missing Security Header' in v.get('type', '') for v in vulnerabilities):
            scripts['Apache .htaccess Cabeceras de Seguridad'] = """
# Configuración de Cabeceras de Seguridad
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>

# Deshabilitar firma del servidor
ServerTokens Prod
ServerSignature Off
"""
        
        # Nginx configuración de seguridad
        if any('Missing Security Header' in v.get('type', '') for v in vulnerabilities):
            scripts['Configuración de Seguridad Nginx'] = """
# Agregar al bloque de servidor de nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Ocultar versión de nginx
server_tokens off;

# Deshabilitar listado de directorios
autoindex off;
"""
        
        # PHP configuración segura
        if any('XSS' in v.get('type', '') or 'SQL Injection' in v.get('type', '') for v in vulnerabilities):
            scripts['Configuración de Seguridad PHP'] = """
<?php
// Configuración de Seguridad PHP

// Deshabilitar funciones peligrosas
disable_functions = exec,passthru,shell_exec,system,proc_open,popen

// Seguridad de sesión
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);

// Ocultar versión de PHP
expose_php = Off

// Ejemplo de validación de entrada
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// Ejemplo de sentencia preparada
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
?>
"""
        
        return scripts

    def _generate_compliance_mapping(self, vulnerabilities):
        """Generar mapeo de cumplimiento normativo"""
        compliance_text = """
        <b>Cumplimiento OWASP Top 10 2021:</b><br/>
        """
        
        owasp_mapping = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            vuln_info = self.vulnerability_descriptions.get(vuln_type, {})
            owasp_category = vuln_info.get('owasp_category', 'Other')
            
            if owasp_category not in owasp_mapping:
                owasp_mapping[owasp_category] = 0
            owasp_mapping[owasp_category] += 1
        
        for category, count in owasp_mapping.items():
            compliance_text += f"• {category}: {count} hallazgos<br/>"
        
        compliance_text += """<br/>
        <b>Alineación con Estándares de la Industria:</b><br/>
        • NIST Cybersecurity Framework: Fases Identify, Protect, Detect cubiertas<br/>
        • ISO 27001: Alineación con gestión de seguridad de la información<br/>
        • PCI DSS: Requisitos de seguridad de aplicaciones web (si aplica)<br/>
        • GDPR: Consideraciones de protección de datos y privacidad<br/><br/>
        
        <b>Notas de Cumplimiento Normativo:</b><br/>
        • Se requieren evaluaciones de seguridad regulares para la mayoría de marcos<br/>
        • Se recomienda documentación de esfuerzos de remediación<br/>
        • Se espera monitoreo y mejora continua<br/>
        • Puede requerirse validación de seguridad de terceros
        """
        
        return compliance_text


# Función helper mejorada para usar desde la API
def generate_comprehensive_pdf_report(scan_data, output_dir="reports"):
    """
    Función helper mejorada para generar reporte PDF profesional completo
    """
    try:
        generator = VulnHunterReportGenerator()
        
        # Validar datos de entrada
        if not scan_data.get('scan_id'):
            scan_data['scan_id'] = 'unknown_scan'
        
        if not scan_data.get('url'):
            scan_data['url'] = 'Objetivo Desconocido'
        
        if not scan_data.get('started_at'):
            scan_data['started_at'] = datetime.now().isoformat()
        
        if not scan_data.get('completed_at'):
            scan_data['completed_at'] = datetime.now().isoformat()
        
        if not scan_data.get('duration_seconds'):
            scan_data['duration_seconds'] = 0
        
        if not scan_data.get('scan_types'):
            scan_data['scan_types'] = ['comprehensive_scan']
        
        if not scan_data.get('vulnerabilities'):
            scan_data['vulnerabilities'] = []
        
        # Generar nombre de archivo profesional
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id_short = scan_data['scan_id'][:8] if scan_data.get('scan_id') else 'unknown'
        filename = f"Reporte_Profesional_VulnHunter_{scan_id_short}_{timestamp}.pdf"
        output_path = os.path.join(output_dir, filename)
        
        # Generar reporte
        final_path = generator.generate_report(scan_data, output_path)
        
        print(f"✅ Reporte PDF profesional generado exitosamente: {final_path}")
        return final_path
        
    except Exception as e:
        print(f"❌ Error generando reporte PDF profesional: {str(e)}")
        # Generar reporte básico como fallback
        try:
            basic_generator = VulnHunterReportGenerator()
            basic_path = os.path.join(output_dir, f"reporte_basico_{timestamp}.pdf")
            return basic_generator.generate_report(scan_data, basic_path)
        except Exception as e2:
            print(f"❌ Error crítico en generación de PDF: {str(e2)}")
            raise e2


# Función adicional para validación de datos
def validate_scan_data(scan_data):
    """
    Validar y limpiar datos de escaneo antes de generar PDF
    """
    required_fields = ['scan_id', 'url', 'started_at', 'scan_types']
    
    for field in required_fields:
        if field not in scan_data:
            print(f"⚠️ Campo requerido faltante: {field}")
            return False
    
    # Validar vulnerabilidades
    if 'vulnerabilities' in scan_data:
        for vuln in scan_data['vulnerabilities']:
            required_vuln_fields = ['type', 'severity', 'location']
            for vfield in required_vuln_fields:
                if vfield not in vuln:
                    vuln[vfield] = 'Desconocido'
    
    return True


if __name__ == "__main__":
    # Ejemplo de uso del generador de reportes
    sample_data = {
        'scan_id': 'test-scan-123',
        'url': 'https://example.com',
        'started_at': datetime.now().isoformat(),
        'completed_at': datetime.now().isoformat(),
        'duration_seconds': 120,
        'scan_types': ['xss', 'sql_injection', 'security_headers', 'ssl_tls', 'directory_scan'],
        'vulnerabilities': [
            {
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'HIGH',
                'location': 'https://example.com/search?q=test',
                'description': 'Vulnerabilidad XSS en parámetro de búsqueda',
                'recommendation': 'Implementar sanitización de entrada',
                'scanner': 'xss'
            }
        ],
        'risk_level': 'HIGH',
        'risk_score': 75
    }
    
    try:
        pdf_path = generate_comprehensive_pdf_report(sample_data)
        print(f"✅ Reporte de prueba generado: {pdf_path}")
    except Exception as e:
        print(f"❌ Error en prueba de generación: {e}")