from pathlib import Path
from math import cos, sin, pi

from PIL import Image, ImageDraw, ImageFilter
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE, MSO_CONNECTOR
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "Fase 2"
OUT_DIR.mkdir(parents=True, exist_ok=True)
PPTX_PATH = OUT_DIR / "Presentacion_VulnHunter_Proyecto_Titulo.pptx"
BG_PATH = OUT_DIR / ".vulnhunter_presentation_bg.png"

W, H = 1600, 900
NAVY = RGBColor(5, 14, 35)
WHITE = RGBColor(245, 248, 255)
MUTED = RGBColor(184, 198, 224)
CYAN = RGBColor(24, 208, 255)
PINK = RGBColor(239, 69, 255)
PURPLE = RGBColor(118, 92, 255)
GREEN = RGBColor(65, 220, 156)
YELLOW = RGBColor(255, 207, 84)
RED = RGBColor(255, 92, 111)


def make_background(path: Path) -> None:
    img = Image.new("RGB", (W, H), (4, 12, 32))
    px = img.load()
    for y in range(H):
        for x in range(W):
            t = x / W
            u = y / H
            r = int(5 + 12 * t + 7 * u)
            g = int(14 + 8 * t + 2 * u)
            b = int(35 + 35 * t + 18 * u)
            px[x, y] = (r, g, b)

    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(glow)
    draw.ellipse((1050, -250, 1750, 450), fill=(234, 63, 255, 105))
    draw.ellipse((-260, 560, 420, 1210), fill=(17, 204, 255, 90))
    glow = glow.filter(ImageFilter.GaussianBlur(105))
    img = Image.alpha_composite(img.convert("RGBA"), glow)

    lines = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(lines)
    for radius in (105, 155, 210):
        draw.ellipse((1310-radius, 115-radius, 1310+radius, 115+radius), outline=(255, 255, 255, 22), width=2)
    for a in range(0, 360, 30):
        x1 = 1310 + 220 * cos(a * pi / 180)
        y1 = 115 + 220 * sin(a * pi / 180)
        x2 = 1310 + 310 * cos(a * pi / 180)
        y2 = 115 + 310 * sin(a * pi / 180)
        draw.line((x1, y1, x2, y2), fill=(46, 217, 255, 24), width=2)
    img = Image.alpha_composite(img, lines)
    img.convert("RGB").save(path, quality=95)


def set_slide_bg(slide):
    slide.shapes.add_picture(str(BG_PATH), 0, 0, width=Inches(13.333), height=Inches(7.5))


def add_text(slide, text, x, y, w, h, size=20, color=WHITE, bold=False,
             font="Aptos", align=PP_ALIGN.LEFT, valign=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.clear()
    tf.word_wrap = True
    tf.vertical_anchor = valign
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.name = font
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    return box


def add_title(slide, kicker, title, subtitle=None):
    add_text(slide, kicker.upper(), 0.65, 0.42, 5.8, 0.3, 10, CYAN, True)
    add_text(slide, title, 0.65, 0.78, 11.7, 0.8, 30, WHITE, True)
    if subtitle:
        add_text(slide, subtitle, 0.68, 1.55, 11.4, 0.5, 13, MUTED)
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.65), Inches(2.02), Inches(1.2), Inches(0.035))
    line.fill.solid(); line.fill.fore_color.rgb = PINK; line.line.fill.background()


def add_footer(slide, n):
    add_text(slide, "VULNHUNTER · MVP DE SEGURIDAD WEB", 0.65, 7.13, 5.0, 0.18, 8, MUTED)
    add_text(slide, f"{n:02d}", 12.1, 7.08, 0.5, 0.22, 9, CYAN, True, align=PP_ALIGN.RIGHT)


def card(slide, x, y, w, h, title, body, accent=CYAN, title_size=16, body_size=11):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid(); shape.fill.fore_color.rgb = RGBColor(12, 27, 58); shape.fill.transparency = 10
    shape.line.color.rgb = RGBColor(50, 74, 118); shape.line.transparency = 30
    band = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(0.08), Inches(h))
    band.fill.solid(); band.fill.fore_color.rgb = accent; band.line.fill.background()
    add_text(slide, title, x + 0.22, y + 0.18, w - 0.38, 0.34, title_size, WHITE, True)
    add_text(slide, body, x + 0.22, y + 0.62, w - 0.38, h - 0.78, body_size, MUTED)


def pill(slide, text, x, y, w, color=PURPLE):
    s = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(0.42))
    s.fill.solid(); s.fill.fore_color.rgb = color; s.fill.transparency = 8
    s.line.fill.background()
    add_text(slide, text, x, y + 0.04, w, 0.25, 10, WHITE, True, align=PP_ALIGN.CENTER)


def connector(slide, x1, y1, x2, y2, color=CYAN):
    line = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    line.line.color.rgb = color
    line.line.width = Pt(1.5)
    return line


def add_notes(slide, text):
    try:
        slide.notes_slide.notes_text_frame.text = text
    except Exception:
        pass


def build():
    make_background(BG_PATH)
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    # 1 — Portada
    s = prs.slides.add_slide(blank); set_slide_bg(s)
    add_text(s, "PROYECTO DE TÍTULO · INGENIERÍA EN INFORMÁTICA", 0.72, 0.72, 7.5, 0.3, 11, CYAN, True)
    add_text(s, "VulnHunter", 0.68, 1.35, 7.5, 0.95, 46, WHITE, True)
    add_text(s, "Monitoreo autorizado de vulnerabilidades web para pymes", 0.72, 2.32, 7.2, 0.72, 22, MUTED)
    pill(s, "MVP FUNCIONAL", 0.72, 3.35, 1.55, GREEN)
    pill(s, "FASTAPI + REACT", 2.45, 3.35, 1.85, PURPLE)
    pill(s, "DOCKER + AWS", 4.48, 3.35, 1.75, PINK)
    add_text(s, "Nicolás Maturana · Carlos Rivera · Diego Quintana · Ignacio Wagner", 0.72, 5.92, 8.5, 0.42, 13, WHITE, True)
    add_text(s, "2026", 0.72, 6.38, 2.0, 0.32, 11, MUTED)
    # decorative shield
    sh = s.shapes.add_shape(MSO_SHAPE.HEXAGON, Inches(9.35), Inches(1.25), Inches(2.45), Inches(2.8))
    sh.fill.solid(); sh.fill.fore_color.rgb = PURPLE; sh.fill.transparency = 25
    sh.line.color.rgb = CYAN; sh.line.width = Pt(2)
    add_text(s, "VH", 9.35, 2.05, 2.45, 0.75, 38, WHITE, True, align=PP_ALIGN.CENTER)
    add_notes(s, "Presentar VulnHunter como un MVP académico con proyección real. Aclarar que los escaneos se realizan únicamente sobre sitios propios o expresamente autorizados.")

    # 2 — Qué es
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "01 · Introducción", "¿Qué es VulnHunter?")
    add_text(s, "Una plataforma que centraliza el ciclo de evaluación de seguridad web: registra activos, ejecuta análisis autorizados, conserva evidencia y genera reportes comprensibles.", 0.75, 2.38, 6.0, 1.6, 22, WHITE, True)
    card(s, 7.25, 2.3, 2.45, 1.55, "Diagnóstico", "Detecta configuraciones débiles y posibles vulnerabilidades.", CYAN)
    card(s, 9.95, 2.3, 2.45, 1.55, "Trazabilidad", "Mantiene historial de escaneos, hallazgos y evolución.", PINK)
    card(s, 7.25, 4.15, 2.45, 1.55, "Evidencia", "Entrega ubicación, severidad, confianza y recomendación.", PURPLE)
    card(s, 9.95, 4.15, 2.45, 1.55, "Reporte", "Genera un PDF profesional para apoyar la corrección.", GREEN)
    add_footer(s, 2)
    add_notes(s, "Evitar describir la herramienta como un reemplazo de un pentest. Es una plataforma de apoyo, priorización y seguimiento.")

    # 3 — Problema y oportunidad
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "02 · Contexto", "Problema y oportunidad", "Las pymes necesitan visibilidad de seguridad sin depender de procesos complejos o costosos.")
    card(s, 0.75, 2.4, 3.75, 2.55, "Problema", "• Escasa visibilidad sobre riesgos web\n• Revisiones manuales y esporádicas\n• Resultados técnicos difíciles de interpretar\n• Falta de seguimiento después de corregir", RED, 18, 13)
    card(s, 4.8, 2.4, 3.75, 2.55, "Propuesta", "• Escaneo centralizado y repetible\n• Priorización por severidad y confianza\n• Evidencia y recomendaciones claras\n• Historial para demostrar mejoras", CYAN, 18, 13)
    card(s, 8.85, 2.4, 3.75, 2.55, "Enfoque ético", "• Solo activos autorizados\n• Validación previa del sitio\n• Control del alcance\n• Hallazgos sujetos a revisión profesional", GREEN, 18, 13)
    add_text(s, "Valor central: transformar señales técnicas en decisiones de corrección comprensibles y trazables.", 1.3, 5.5, 10.7, 0.55, 18, WHITE, True, align=PP_ALIGN.CENTER)
    add_footer(s, 3)

    # 4 — Objetivos
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "03 · Alcance", "Objetivos del MVP")
    card(s, 0.75, 2.32, 5.5, 3.15, "Objetivo general", "Desarrollar una plataforma web capaz de ejecutar evaluaciones de seguridad autorizadas, gestionar sus resultados y entregar evidencia útil para apoyar la mitigación de riesgos en sitios de pequeñas empresas.", PINK, 20, 16)
    card(s, 6.55, 2.32, 2.75, 1.42, "01 · Integrar", "Frontend, API, persistencia y procesamiento asíncrono.", CYAN)
    card(s, 9.6, 2.32, 2.75, 1.42, "02 · Detectar", "Cinco categorías iniciales con criterios conservadores.", PURPLE)
    card(s, 6.55, 4.05, 2.75, 1.42, "03 · Reportar", "Evidencia, severidad, confianza y recomendaciones.", GREEN)
    card(s, 9.6, 4.05, 2.75, 1.42, "04 · Demostrar", "Flujo reproducible con laboratorio autorizado.", YELLOW)
    add_footer(s, 4)

    # 5 — Servicios/scanners
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "04 · Motor de análisis", "Cobertura actual de scanners", "Un MVP enfocado en calidad de evidencia antes que cantidad de alertas.")
    items = [
        ("SQL Injection", "Errores de motor introducidos por el payload y comparación con línea base.", RED),
        ("XSS", "Reflexión dinámica validada en un contexto potencialmente ejecutable.", PINK),
        ("Headers", "Controles esenciales: CSP, clickjacking, MIME y HSTS cuando corresponde.", CYAN),
        ("SSL/TLS", "Validez, vencimiento y problemas de negociación o certificado.", GREEN),
        ("Archivos sensibles", "Evidencia de contenido y detección de soft-404 para evitar alertas falsas.", YELLOW),
    ]
    positions = [(0.75,2.35),(4.68,2.35),(8.61,2.35),(2.72,4.45),(6.65,4.45)]
    for (title, body, color), (x,y) in zip(items, positions):
        card(s, x, y, 3.65, 1.65, title, body, color, 16, 11)
    add_footer(s, 5)

    # 6 — Arquitectura
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "05 · Diseño técnico", "Arquitectura del sistema", "Arquitectura modular/hexagonal y servicios desacoplados mediante contenedores.")
    nodes = [
        ("React", 0.65, 3.0, CYAN), ("Nginx", 2.55, 3.0, PURPLE), ("FastAPI", 4.45, 3.0, PINK),
        ("PostgreSQL", 7.15, 2.35, GREEN), ("Redis", 7.15, 3.9, RED),
        ("Celery", 9.65, 3.9, YELLOW), ("Scanners", 9.65, 2.35, CYAN),
        ("PDF", 11.55, 3.0, PURPLE),
    ]
    for title, x, y, color in nodes:
        shp = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(1.35), Inches(0.82))
        shp.fill.solid(); shp.fill.fore_color.rgb = RGBColor(13, 31, 65)
        shp.line.color.rgb = color; shp.line.width = Pt(2)
        add_text(s, title, x, y+0.22, 1.35, 0.3, 11, WHITE, True, align=PP_ALIGN.CENTER)
    for a,b in [((2.0,3.41),(2.55,3.41)),((3.9,3.41),(4.45,3.41)),((5.8,3.25),(7.15,2.75)),((5.8,3.55),(7.15,4.31)),((8.5,4.31),(9.65,4.31)),((8.5,2.76),(9.65,2.76)),((11.0,2.9),(11.55,3.25))]: connector(s,*a,*b)
    add_text(s, "Docker Compose", 4.6, 5.55, 4.1, 0.45, 17, WHITE, True, align=PP_ALIGN.CENTER)
    pill(s, "DESARROLLO REPRODUCIBLE", 5.12, 6.05, 3.05, PURPLE)
    add_footer(s, 6)
    add_notes(s, "Explicar que React consume /api en el mismo origen; Nginx redirige internamente a FastAPI. Redis actúa como broker y Celery ejecuta trabajos en segundo plano.")

    # 7 — Metodología y flujo
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "06 · Metodología", "Desarrollo incremental y flujo de extremo a extremo")
    steps = ["Registrar\nsitio", "Verificar\nautorización", "Iniciar\nescaneo", "Procesar en\nCelery", "Guardar\nhallazgos", "Visualizar\nprogreso", "Descargar\nPDF"]
    colors = [CYAN, GREEN, PINK, PURPLE, RED, YELLOW, CYAN]
    for i,(txt,col) in enumerate(zip(steps,colors)):
        x=0.45+i*1.82
        c=s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(2.7), Inches(1.28), Inches(1.28))
        c.fill.solid(); c.fill.fore_color.rgb=RGBColor(11,28,61); c.line.color.rgb=col; c.line.width=Pt(2.5)
        add_text(s, str(i+1), x+0.43, 2.88, 0.42, 0.35, 17, col, True, align=PP_ALIGN.CENTER)
        add_text(s, txt, x-0.15, 4.05, 1.58, 0.65, 12, WHITE, True, align=PP_ALIGN.CENTER)
        if i<6: connector(s,x+1.28,3.34,x+1.82,3.34,MUTED)
    pill(s, "RAMAS + PULL REQUEST", 1.1, 5.18, 2.35, PURPLE)
    pill(s, "DOCKER", 3.72, 5.18, 1.45, CYAN)
    pill(s, "PRUEBAS CONTROLADAS", 5.44, 5.18, 2.45, GREEN)
    pill(s, "MEJORA ITERATIVA", 8.16, 5.18, 2.05, PINK)
    add_text(s, "Cada incremento se integra, prueba y documenta antes de ampliar el alcance del scanner.", 1.35, 5.9, 10.65, 0.5, 15, MUTED, align=PP_ALIGN.CENTER)
    add_footer(s, 7)

    # 8 — Precisión
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "07 · Calidad", "Reducción de falsos positivos", "La herramienta no reporta cualquier diferencia como vulnerabilidad.")
    card(s, 0.75, 2.35, 3.75, 2.7, "Antes", "Cambios de tamaño, códigos HTTP genéricos o reflexiones de texto podían elevar el ruido y disminuir la confianza en el reporte.", RED, 20, 15)
    card(s, 4.8, 2.35, 3.75, 2.7, "Mejora aplicada", "• Línea base de respuesta\n• Tokens únicos\n• Evidencia específica del motor\n• Detección de soft-404\n• Confianza conservadora", CYAN, 20, 14)
    card(s, 8.85, 2.35, 3.75, 2.7, "Resultado esperado", "Menos alertas, pero con mejor trazabilidad. Los casos no concluyentes deben presentarse como señales para revisión manual.", GREEN, 20, 15)
    pill(s, "PRINCIPIO: PRECISIÓN > VOLUMEN", 4.85, 5.65, 3.7, PINK)
    add_footer(s, 8)

    # 9 — Resultados verificables
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "08 · Resultados", "¿Qué se encuentra implementado?", "Estado verificable del MVP, sin confundir funcionalidades futuras con resultados actuales.")
    results = [
        ("5", "SCANNERS", "SQLi, XSS, headers, SSL/TLS y archivos sensibles", CYAN),
        ("E2E", "FLUJO INTEGRADO", "React → FastAPI → PostgreSQL → PDF", GREEN),
        ("ASYNC", "PROCESAMIENTO", "Redis y Celery para ejecutar trabajos", PURPLE),
        ("CLOUD", "DESPLIEGUE", "Docker en AWS EC2 y acceso HTTPS temporal", PINK),
    ]
    xs=[0.65,3.78,6.91,10.04]
    for x,(big,title,body,col) in zip(xs,results):
        shape=s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(2.45), Inches(2.65), Inches(2.7))
        shape.fill.solid(); shape.fill.fore_color.rgb=RGBColor(12,27,58); shape.line.color.rgb=col; shape.line.width=Pt(2)
        add_text(s,big,x+0.2,2.77,2.25,0.62,28,col,True,align=PP_ALIGN.CENTER)
        add_text(s,title,x+0.2,3.48,2.25,0.35,13,WHITE,True,align=PP_ALIGN.CENTER)
        add_text(s,body,x+0.28,4.02,2.09,0.72,11,MUTED,align=PP_ALIGN.CENTER)
    add_text(s, "Validación pendiente: medir precisión, tiempos y cobertura sobre un laboratorio con vulnerabilidades conocidas.", 1.2, 5.72, 10.95, 0.6, 16, YELLOW, True, align=PP_ALIGN.CENTER)
    add_footer(s, 9)

    # 10 — Despliegue
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "09 · Infraestructura", "Despliegue del MVP en AWS", "Entorno de demostración controlado y reproducible.")
    card(s, 0.75, 2.35, 2.75, 2.5, "AWS EC2", "Amazon Linux 2023\nInstancia t3.small\nVolumen EBS cifrado\nAcceso administrativo mediante SSM", CYAN, 18, 13)
    card(s, 3.78, 2.35, 2.75, 2.5, "Docker", "Frontend, API, worker, PostgreSQL y Redis desplegados como servicios independientes.", PURPLE, 18, 13)
    card(s, 6.81, 2.35, 2.75, 2.5, "Cloudflare", "Quick Tunnel HTTPS para demostraciones; URL temporal y posibilidad de control por correo.", PINK, 18, 13)
    card(s, 9.84, 2.35, 2.75, 2.5, "Seguridad", "Sin puertos entrantes públicos. Secretos fuera de Git y acceso operativo con MFA/IAM.", GREEN, 18, 13)
    add_text(s, "Pendiente para producción: dominio propio, Named Tunnel, copias de seguridad, monitoreo y endurecimiento del entorno.", 1.15, 5.45, 11.0, 0.7, 16, YELLOW, True, align=PP_ALIGN.CENTER)
    add_footer(s, 10)

    # 11 — Diferenciación y límites
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "10 · Evaluación", "Aporte, alcance y limitaciones")
    card(s, 0.65, 2.25, 3.75, 3.05, "Aporte del proyecto", "• Unifica evaluación y seguimiento\n• Entrega evidencia comprensible\n• Mantiene historial de mejoras\n• Orientación inicial a pymes\n• Arquitectura preparada para crecer", CYAN, 19, 14)
    card(s, 4.78, 2.25, 3.75, 3.05, "Alcance del MVP", "• Cinco categorías iniciales\n• Sitios propios o autorizados\n• Ejecución manual del escaneo\n• Dashboard y reporte PDF\n• Despliegue demostrativo en AWS", GREEN, 19, 14)
    card(s, 8.91, 2.25, 3.75, 3.05, "Limitaciones reconocidas", "• No reemplaza un pentest\n• No garantiza cobertura total\n• Requiere revisión humana\n• Validación estadística pendiente\n• Quick Tunnel no es producción", YELLOW, 19, 14)
    add_text(s, "La honestidad técnica sobre los límites aumenta la confianza y define una evolución medible.", 1.2, 5.78, 10.95, 0.55, 16, WHITE, True, align=PP_ALIGN.CENTER)
    add_footer(s, 11)

    # 12 — Demo / QR
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "11 · Demostración", "Ruta sugerida para la presentación")
    card(s, 0.75, 2.25, 6.9, 3.75, "Demostración en vivo", "1. Acceso al entorno mediante HTTPS\n2. Registro/selección de un sitio autorizado\n3. Ejecución del escaneo\n4. Progreso procesado por Celery\n5. Hallazgo conocido y su evidencia\n6. Descarga del reporte PDF\n7. Consulta del registro persistido", CYAN, 20, 15)
    qr = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.55), Inches(2.25), Inches(3.05), Inches(3.05))
    qr.fill.solid(); qr.fill.fore_color.rgb = WHITE; qr.line.color.rgb = PINK; qr.line.width = Pt(3)
    add_text(s, "INSERTAR QR\nDEL TÚNEL ACTIVO", 8.77, 3.25, 2.6, 0.85, 20, NAVY, True, align=PP_ALIGN.CENTER)
    add_text(s, "La URL de Quick Tunnel cambia al reiniciar.", 8.25, 5.58, 3.65, 0.5, 11, MUTED, align=PP_ALIGN.CENTER)
    add_footer(s, 12)

    # 13 — Cierre
    s = prs.slides.add_slide(blank); set_slide_bg(s); add_title(s, "12 · Conclusión", "VulnHunter: un MVP realista con proyección")
    add_text(s, "El proyecto demuestra un flujo completo y técnicamente defendible: desde la autorización y el escaneo hasta la persistencia, visualización y generación del reporte.", 0.85, 2.05, 7.1, 1.35, 23, WHITE, True)
    card(s, 8.45, 2.05, 3.75, 1.35, "Fortaleza", "Integración real y evidencia trazable.", GREEN, 16, 13)
    card(s, 8.45, 3.62, 3.75, 1.35, "Límite reconocido", "No reemplaza un pentest profesional.", YELLOW, 16, 13)
    card(s, 8.45, 5.19, 3.75, 1.35, "Siguiente etapa", "Validación, backups, monitoreo y dominio estable.", PINK, 16, 13)
    add_text(s, "Próximos pasos", 0.85, 3.75, 3.2, 0.45, 20, CYAN, True)
    add_text(s, "Validar con laboratorio conocido · completar autorización de sitios · respaldos y monitoreo · dominio y túnel estable", 0.9, 4.25, 6.7, 1.05, 14, MUTED)
    add_text(s, "Gracias", 0.85, 5.5, 4.0, 0.62, 31, WHITE, True)
    add_text(s, "Nicolás · Carlos · Diego · Ignacio", 0.9, 6.17, 5.5, 0.35, 13, MUTED)
    add_footer(s, 13)
    add_notes(s, "Cerrar destacando que el valor no está en prometer detectar todo, sino en presentar un proceso autorizado, reproducible, medible y técnicamente honesto.")

    prs.save(PPTX_PATH)
    BG_PATH.unlink(missing_ok=True)
    print(PPTX_PATH)
    print(f"slides={len(prs.slides)} bytes={PPTX_PATH.stat().st_size}")


if __name__ == "__main__":
    build()
