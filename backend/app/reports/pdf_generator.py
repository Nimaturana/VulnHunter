# app/reports/pdf_generator.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus import PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from io import BytesIO
import base64

class WebSecurityReportGenerator:
    """Generador de reportes PDF profesionales para escaneos de seguridad web"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Configurar estilos personalizados para el reporte"""
        
        # Título principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1f2937'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtítulo
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.HexColor('#374151'),
            fontName='Helvetica-Bold'
        ))
        
        # Texto de riesgo crítico
        self.styles.add(ParagraphStyle(
            name='CriticalRisk',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.red,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            spaceAfter=10
        ))
        
        # Texto de riesgo alto
        self.styles.add(ParagraphStyle(
            name='HighRisk',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#f59e0b'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            spaceAfter=10
        ))
        
        # Texto de riesgo medio
        self.styles.add(ParagraphStyle(
            name='MediumRisk',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#10b981'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            spaceAfter=10
        ))
        
        # Texto normal mejorado
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            alignment=TA_JUSTIFY,
            fontName='Helvetica'
        ))

    def generate_report(self, scan_data, output_path=None):
        """Generar reporte PDF completo"""
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/security_report_{scan_data['scan_id']}_{timestamp}.pdf"
        
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Crear documento
        doc = SimpleDocTemplate(output_path, pagesize=A4,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        # Construir contenido
        story = []
        
        # Página de portada
        story.extend(self._create_cover_page(scan_data))
        story.append(PageBreak())
        
        # Resumen ejecutivo
        story.extend(self._create_executive_summary(scan_data))
        story.append(PageBreak())
        
        # Detalles de vulnerabilidades
        story.extend(self._create_vulnerability_details(scan_data))
        story.append(PageBreak())
        
        # Recomendaciones
        story.extend(self._create_recommendations(scan_data))
        story.append(PageBreak())
        
        # Anexos técnicos
        story.extend(self._create_technical_appendix(scan_data))
        
        # Generar PDF
        doc.build(story)
        return output_path

    def _create_cover_page(self, scan_data):
        """Crear página de portada"""
        story = []
        
        # Logo/Título de empresa
        story.append(Paragraph("WebSecure Pro", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Título del reporte
        story.append(Paragraph("REPORTE DE SEGURIDAD WEB", self.styles['CustomTitle']))
        story.append(Spacer(1, 30))
        
        # Información del sitio
        site_info = f"""
        <b>Sitio web analizado:</b> {scan_data['url']}<br/>
        <b>Fecha de escaneo:</b> {datetime.fromisoformat(scan_data['started_at'].replace('Z', '+00:00')).strftime('%d de %B, %Y')}<br/>
        <b>ID de escaneo:</b> {scan_data['scan_id']}<br/>
        <b>Duración del escaneo:</b> {scan_data['duration_seconds']} segundos
        """
        story.append(Paragraph(site_info, self.styles['CustomNormal']))
        story.append(Spacer(1, 40))
        
        # Nivel de riesgo prominente
        risk_level = scan_data.get('risk_level', 'UNKNOWN')
        risk_score = scan_data.get('risk_score', 0)
        
        if risk_level == 'CRITICAL':
            risk_style = 'CriticalRisk'
            risk_text = f"🚨 RIESGO CRÍTICO - Puntuación: {risk_score}/10"
        elif risk_level == 'HIGH':
            risk_style = 'HighRisk' 
            risk_text = f"⚠️ RIESGO ALTO - Puntuación: {risk_score}/10"
        elif risk_level == 'MEDIUM':
            risk_style = 'MediumRisk'
            risk_text = f"⚡ RIESGO MEDIO - Puntuación: {risk_score}/10"
        else:
            risk_style = 'MediumRisk'
            risk_text = f"✅ RIESGO BAJO - Puntuación: {risk_score}/10"
        
        story.append(Paragraph(risk_text, self.styles[risk_style]))
        story.append(Spacer(1, 30))
        
        # Resumen de vulnerabilidades
        total_vulns = len(scan_data.get('vulnerabilities', []))
        summary_text = f"""
        <b>RESUMEN DE HALLAZGOS:</b><br/>
        • Total de vulnerabilidades encontradas: <b>{total_vulns}</b><br/>
        • Tipos de escaneo realizados: {', '.join(scan_data['scan_types'])}<br/>
        • Estado del escaneo: <b>{scan_data['status'].upper()}</b>
        """
        story.append(Paragraph(summary_text, self.styles['CustomNormal']))
        
        return story

    def _create_executive_summary(self, scan_data):
        """Crear resumen ejecutivo"""
        story = []
        
        story.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomSubtitle']))
        
        # Contexto del escaneo
        context = f"""
        Este reporte presenta los resultados del análisis de seguridad web realizado en {scan_data['url']} 
        el {datetime.fromisoformat(scan_data['started_at'].replace('Z', '+00:00')).strftime('%d de %B, %Y')}. 
        El escaneo se realizó utilizando técnicas automatizadas de detección de vulnerabilidades, 
        enfocándose en las amenazas más comunes según el OWASP Top 10.
        """
        story.append(Paragraph(context, self.styles['CustomNormal']))
        story.append(Spacer(1, 20))
        
        # Hallazgos principales
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if vulnerabilities:
            story.append(Paragraph("HALLAZGOS PRINCIPALES:", self.styles['CustomSubtitle']))
            
            # Contar por severidad
            critical_count = len([v for v in vulnerabilities if v['severity'] == 'CRITICAL'])
            high_count = len([v for v in vulnerabilities if v['severity'] == 'HIGH'])
            medium_count = len([v for v in vulnerabilities if v['severity'] == 'MEDIUM'])
            low_count = len([v for v in vulnerabilities if v['severity'] == 'LOW'])
            
            findings_summary = f"""
            • <b>{critical_count}</b> vulnerabilidades CRÍTICAS que requieren atención inmediata<br/>
            • <b>{high_count}</b> vulnerabilidades de riesgo ALTO<br/>
            • <b>{medium_count}</b> vulnerabilidades de riesgo MEDIO<br/>
            • <b>{low_count}</b> vulnerabilidades de riesgo BAJO
            """
            story.append(Paragraph(findings_summary, self.styles['CustomNormal']))
            story.append(Spacer(1, 20))
            
            # Recomendación ejecutiva
            story.append(Paragraph("RECOMENDACIÓN EJECUTIVA:", self.styles['CustomSubtitle']))
            
            risk_level = scan_data.get('risk_level', 'UNKNOWN')
            recommendations = {
                'CRITICAL': """
                <b>ACCIÓN INMEDIATA REQUERIDA:</b> Se han identificado vulnerabilidades críticas que exponen 
                el sitio web a ataques severos. Se recomienda suspender operaciones no esenciales hasta 
                que se implementen las correcciones necesarias.
                """,
                'HIGH': """
                <b>ATENCIÓN PRIORITARIA:</b> Las vulnerabilidades identificadas representan un riesgo 
                significativo para la seguridad. Se recomienda implementar las correcciones en un 
                plazo no mayor a 48-72 horas.
                """,
                'MEDIUM': """
                <b>REVISIÓN PROGRAMADA:</b> Se han identificado vulnerabilidades que deben ser abordadas 
                en el próximo ciclo de mantenimiento. Aunque no representan un riesgo inmediato, 
                requieren atención en las próximas semanas.
                """,
                'LOW': """
                <b>MANTENIMIENTO RUTINARIO:</b> El sitio web presenta un nivel de seguridad aceptable 
                con oportunidades menores de mejora. Se recomienda implementar las sugerencias como 
                parte del mantenimiento regular.
                """
            }
            
            exec_recommendation = recommendations.get(risk_level, 
                "Se recomienda revisar los hallazgos detallados y implementar las correcciones sugeridas.")
            
            story.append(Paragraph(exec_recommendation, self.styles['CustomNormal']))
        else:
            story.append(Paragraph("✅ No se encontraron vulnerabilidades críticas en este escaneo.", 
                                 self.styles['CustomNormal']))
        
        return story

    def _create_vulnerability_details(self, scan_data):
        """Crear sección de detalles de vulnerabilidades"""
        story = []
        
        story.append(Paragraph("DETALLES DE VULNERABILIDADES", self.styles['CustomSubtitle']))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            story.append(Paragraph("No se encontraron vulnerabilidades en este escaneo.", 
                                 self.styles['CustomNormal']))
            return story
        
        # Agrupar por tipo
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        for vuln_type, vuln_list in vuln_by_type.items():
            # Título del tipo de vulnerabilidad
            story.append(Paragraph(f"{vuln_type.upper()}", self.styles['CustomSubtitle']))
            
            for i, vuln in enumerate(vuln_list, 1):
                # Crear tabla con detalles de la vulnerabilidad
                vuln_data = [
                    ['Campo', 'Valor'],
                    ['Severidad', vuln.get('severity', 'N/A')],
                    ['Ubicación', vuln.get('location', 'N/A')],
                    ['Descripción', vuln.get('description', 'N/A')],
                    ['Recomendación', vuln.get('recommendation', 'N/A')]
                ]
                
                # Agregar evidencia si existe
                if vuln.get('evidence'):
                    vuln_data.append(['Evidencia', vuln.get('evidence')])
                
                vuln_table = Table(vuln_data, colWidths=[2*inch, 4*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#f3f4f6')),
                    ('TEXTCOLOR', (0, 0), (1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 20))
        
        return story

    def _create_recommendations(self, scan_data):
        """Crear sección de recomendaciones"""
        story = []
        
        story.append(Paragraph("RECOMENDACIONES DE SEGURIDAD", self.styles['CustomSubtitle']))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Recomendaciones generales
        general_recommendations = [
            "Implementar un programa regular de escaneo de vulnerabilidades",
            "Establecer un proceso de gestión de parches y actualizaciones",
            "Configurar monitoreo continuo de seguridad",
            "Realizar pruebas de penetración periódicas",
            "Implementar un Web Application Firewall (WAF)"
        ]
        
        # Recomendaciones específicas basadas en vulnerabilidades encontradas
        specific_recommendations = []
        
        vuln_types = [vuln.get('type', '') for vuln in vulnerabilities]
        
        if any('XSS' in vtype for vtype in vuln_types):
            specific_recommendations.extend([
                "Implementar Content Security Policy (CSP) headers",
                "Sanitizar todas las entradas de usuario",
                "Usar funciones de escape apropiadas para el contexto HTML",
                "Validar y filtrar datos de entrada en el servidor"
            ])
        
        if any('SQL Injection' in vtype for vtype in vuln_types):
            specific_recommendations.extend([
                "Usar prepared statements para todas las consultas SQL",
                "Implementar validación estricta de parámetros de entrada",
                "Aplicar principio de menor privilegio en cuentas de base de datos",
                "Considerar el uso de un ORM (Object-Relational Mapping)"
            ])
        
        # Combinar recomendaciones
        all_recommendations = specific_recommendations + general_recommendations
        
        # Crear lista numerada
        for i, rec in enumerate(all_recommendations[:10], 1):  # Limitar a 10 recomendaciones
            story.append(Paragraph(f"{i}. {rec}", self.styles['CustomNormal']))
            story.append(Spacer(1, 6))
        
        # Próximos pasos
        story.append(Spacer(1, 20))
        story.append(Paragraph("PRÓXIMOS PASOS SUGERIDOS:", self.styles['CustomSubtitle']))
        
        next_steps = """
        1. <b>Corto plazo (1-7 días):</b> Abordar vulnerabilidades críticas y de alto riesgo<br/>
        2. <b>Mediano plazo (1-4 semanas):</b> Implementar medidas preventivas y mejoras de seguridad<br/>
        3. <b>Largo plazo (1-3 meses):</b> Establecer programa de seguridad continua y monitoreo<br/>
        4. <b>Seguimiento:</b> Realizar nuevo escaneo después de implementar correcciones
        """
        story.append(Paragraph(next_steps, self.styles['CustomNormal']))
        
        return story

    def _create_technical_appendix(self, scan_data):
        """Crear anexo técnico"""
        story = []
        
        story.append(Paragraph("ANEXO TÉCNICO", self.styles['CustomSubtitle']))
        
        # Información técnica del escaneo
        tech_info = f"""
        <b>Metodología de escaneo:</b><br/>
        • Tipos de escaneo: {', '.join(scan_data['scan_types'])}<br/>
        • Duración total: {scan_data['duration_seconds']} segundos<br/>
        • Fecha y hora de inicio: {scan_data['started_at']}<br/>
        • Fecha y hora de finalización: {scan_data['completed_at']}<br/><br/>
        
        <b>Herramientas utilizadas:</b><br/>
        • WebSecure Pro Scanner v1.0<br/>
        • Módulos: XSS Scanner, SQL Injection Scanner<br/>
        • Base de datos de vulnerabilidades: OWASP Top 10 2021<br/><br/>
        
        <b>Cobertura del escaneo:</b><br/>
        • Análisis de formularios web<br/>
        • Pruebas de parámetros GET y POST<br/>
        • Detección de patrones de vulnerabilidad<br/>
        • Análisis de respuestas del servidor
        """
        
        story.append(Paragraph(tech_info, self.styles['CustomNormal']))
        story.append(Spacer(1, 20))
        
        # Detalles técnicos de los resultados
        results = scan_data.get('results', {})
        
        for scan_type, result_data in results.items():
            story.append(Paragraph(f"DETALLES - {scan_type.upper()}", self.styles['CustomSubtitle']))
            
            if isinstance(result_data, dict):
                tech_details = f"""
                • Tiempo de escaneo: {result_data.get('scan_time', 'N/A')} segundos<br/>
                • Formularios encontrados: {result_data.get('forms_found', 'N/A')}<br/>
                • Parámetros probados: {result_data.get('params_tested', 'N/A')}<br/>
                • Vulnerabilidades detectadas: {len(result_data.get('vulnerabilities', []))}<br/>
                • Estado: {'Vulnerable' if result_data.get('vulnerable') else 'Seguro'}
                """
                story.append(Paragraph(tech_details, self.styles['CustomNormal']))
            
            story.append(Spacer(1, 15))
        
        # Disclaimer
        story.append(Spacer(1, 30))
        story.append(Paragraph("DISCLAIMER", self.styles['CustomSubtitle']))
        disclaimer = """
        Este reporte ha sido generado mediante herramientas automatizadas de escaneo de vulnerabilidades. 
        Los resultados deben ser verificados por personal técnico calificado antes de implementar cualquier 
        corrección. WebSecure Pro no se hace responsable por daños que puedan resultar del uso de esta información. 
        Se recomienda realizar pruebas adicionales en un ambiente controlado antes de aplicar cambios en producción.
        """
        story.append(Paragraph(disclaimer, self.styles['CustomNormal']))
        
        return story

# Función helper para usar desde la API
def generate_pdf_report(scan_data, output_dir="reports"):
    """Función helper para generar reporte PDF desde la API"""
    generator = WebSecurityReportGenerator()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{scan_data['scan_id'][:8]}_{timestamp}.pdf"
    output_path = os.path.join(output_dir, filename)
    
    return generator.generate_report(scan_data, output_path)
