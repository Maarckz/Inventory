from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from collections import Counter
from datetime import datetime
from io import BytesIO
import json
import ast

COLOR_PRIMARY = colors.HexColor("#1A252F")
COLOR_SECONDARY = colors.HexColor("#3498DB")
COLOR_ACCENT = colors.HexColor("#BDC3C7")
COLOR_BG_HEADER = colors.HexColor("#F8F9FA")
COLOR_SUCCESS = colors.HexColor("#27AE60")
COLOR_DANGER = colors.HexColor("#C0392B")

def header_footer(canvas, doc):
    canvas.saveState()
    try:
        canvas.drawImage("static/mlogo.png", 40, letter[1] - 55, width=90, height=25, preserveAspectRatio=True, mask='auto')
    except:
        canvas.setFont("Helvetica-Bold", 16)
        canvas.setFillColor(COLOR_SECONDARY)
        canvas.drawString(40, letter[1] - 50, "INVENTORY")

    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(COLOR_PRIMARY)
    canvas.drawRightString(letter[0] - 40, letter[1] - 40, "RELATÓRIO DE INFRAESTRUTURA")
    canvas.setFillColor(COLOR_SECONDARY)
    canvas.rect(40, letter[1] - 65, letter[0] - 80, 2, fill=1, stroke=0)

    timestamp = datetime.now().strftime('%d/%m/%Y • %H:%M')
    canvas.setStrokeColor(COLOR_ACCENT)
    canvas.line(40, 50, letter[0] - 40, 50)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(40, 35, f"Gerado em: {timestamp}")
    canvas.drawRightString(letter[0] - 40, 35, f"Página {canvas.getPageNumber()}")
    canvas.restoreState()

def get_value(obj, key, default="N/A"):
    """
    Tenta pegar valor seja de um Dicionário ou de um Objeto (SQLAlchemy/Classe).
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    else:
        return getattr(obj, key, default)

def create_pie_chart(machines):
    """Gera gráfico de pizza para OS"""
    os_raw = [str(get_value(m, 'os_name', 'Unknown')).split()[0] for m in machines]
    data_counter = Counter(os_raw)
    
    colors_list = [colors.HexColor(c) for c in ["#3498DB", "#E74C3C", "#F1C40F", "#9B59B6", "#2ECC71", "#34495E"]]
    
    most = data_counter.most_common(5)
    data = [x[1] for x in most] if most else [1]
    labels = [x[0] for x in most] if most else ["Sem dados"]
    
    d = Drawing(200, 150)
    pc = Pie()
    pc.x = 50
    pc.y = 25
    pc.width = 100
    pc.height = 100
    pc.data = data
    pc.labels = None
    
    for i, _ in enumerate(data):
        pc.slices[i].fillColor = colors_list[i % len(colors_list)]
        pc.slices[i].strokeColor = colors.white
        
    legend_data = []
    total = sum(data)
    for i, label in enumerate(labels):
        pct = (data[i]/total)*100 if total > 0 else 0
        legend_data.append((colors_list[i % len(colors_list)], label, f"{pct:.1f}%"))
        
    return d, legend_data

def normalize_details(machine):
    """
    Tenta extrair interfaces e portas de strings JSON ou objetos.
    """
    raw_ifaces = get_value(machine, 'network_interfaces', [])
    if isinstance(raw_ifaces, str):
        try:
            raw_ifaces = json.loads(raw_ifaces)
        except:
            try: raw_ifaces = ast.literal_eval(raw_ifaces)
            except: raw_ifaces = []
            
    ip = get_value(machine, 'ip_address')
    if not raw_ifaces and ip and ip != 'N/A':
        raw_ifaces = [{'name': 'eth0 (default)', 'ip': ip, 'mac': '-'}]
        
    raw_ports = get_value(machine, 'open_ports', [])
    if isinstance(raw_ports, str):
        try:
            raw_ports = json.loads(raw_ports)
        except:
            try: raw_ports = ast.literal_eval(raw_ports)
            except: raw_ports = []

    return raw_ifaces, raw_ports

def generate_pdf_report(stats, machines, include_details=False):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=80, bottomMargin=60, leftMargin=40, rightMargin=40)
    elements = []
    styles = getSampleStyleSheet()

    style_h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, textColor=COLOR_PRIMARY, spaceAfter=10)
    style_h3 = ParagraphStyle('H3', parent=styles['Heading3'], fontName='Helvetica-Bold', fontSize=10, textColor=COLOR_SECONDARY, spaceBefore=10)
    style_cell = ParagraphStyle('Cell', parent=styles['Normal'], fontSize=9)
    style_mono = ParagraphStyle('Mono', parent=styles['Normal'], fontName='Courier', fontSize=8, textColor=COLOR_PRIMARY)
    style_mono_small = ParagraphStyle('MonoSmall', parent=styles['Normal'], fontName='Courier', fontSize=7, textColor=colors.grey)

    elements.append(Paragraph("Visão Geral do Ambiente", style_h2))
    
    chart, legend = create_pie_chart(machines)
    
    t_leg_data = [[ "", label, pct] for c, label, pct in legend]
    t_leg = Table(t_leg_data, colWidths=[15, 80, 40])
    leg_style = [('FONTSIZE', (0,0), (-1,-1), 8), ('VALIGN', (0,0), (-1,-1), 'MIDDLE')]
    for i, item in enumerate(legend):
        leg_style.append(('BACKGROUND', (0,i), (0,i), item[0]))
    t_leg.setStyle(TableStyle(leg_style))
    
    active = stats['status'].get('Ativo', 0)
    inactive = stats['status'].get('Inativo', 0)
    total = active + inactive
    
    metrics_data = [
        [Paragraph(f"<font size=18 color='#1A252F'><b>{total}</b></font><br/><font size=7 color='grey'>TOTAL</font>", styles['Normal'])],
        [Paragraph(f"<font size=18 color='#27AE60'><b>{active}</b></font><br/><font size=7 color='grey'>ATIVOS</font>", styles['Normal'])],
        [Paragraph(f"<font size=18 color='#C0392B'><b>{inactive}</b></font><br/><font size=7 color='grey'>OFFLINE</font>", styles['Normal'])]
    ]
    t_metrics = Table(metrics_data, colWidths=[100], rowHeights=[45,45,45])
    t_metrics.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'RIGHT'), ('LINEBELOW', (0,0), (0,-2), 1, COLOR_BG_HEADER)]))
    
    t_dash = Table([[chart, t_leg, t_metrics]], colWidths=[160, 140, 120])
    t_dash.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
    elements.append(t_dash)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Inventário Resumido", style_h2))
    headers = ["Hostname", "IP", "Sistema", "Status"]
    t_data = [headers]
    
    for m in machines:
        stat = get_value(m, 'device_status', 'Unknown')
        color = COLOR_SUCCESS if str(stat).lower() == 'ativo' else COLOR_DANGER
        
        row = [
            Paragraph(f"<b>{get_value(m, 'hostname')}</b>", style_cell),
            Paragraph(get_value(m, 'ip_address'), style_mono),
            Paragraph(f"{get_value(m, 'os_name')}", style_cell),
            Paragraph(f"<font color='{color.hexval()}'>● {str(stat).upper()}</font>", style_cell)
        ]
        t_data.append(row)
        
    t_main = Table(t_data, colWidths=[130, 120, 180, 80], repeatRows=1)
    t_main.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLOR_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (1,1), (-1,-1), [colors.white, COLOR_BG_HEADER]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(t_main)

    if include_details:
        elements.append(PageBreak())
        elements.append(Paragraph("Detalhamento Técnico de Rede e Serviços", style_h2))
        
        for i, m in enumerate(machines):
            ifaces, ports = normalize_details(m)
            
            hn = get_value(m, 'hostname')
            ip = get_value(m, 'ip_address')
            elements.append(Paragraph(f"{hn} <font color='#7f8c8d' size=9>({ip})</font>", style_h3))
            
            hw_info = [
                [Paragraph("<b>Hardware</b>", style_cell), Paragraph(f"CPU: {get_value(m,'cpu_name')} | RAM: {get_value(m,'ram_total')}GB", style_cell)],
                [Paragraph("<b>OS/Kernel</b>", style_cell), Paragraph(f"{get_value(m,'os_name')} | Kernel: {get_value(m,'os_kernel')}", style_cell)]
            ]
            t_hw = Table(hw_info, colWidths=[80, 440])
            t_hw.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, COLOR_ACCENT),
                ('BACKGROUND', (0,0), (0,-1), COLOR_BG_HEADER)
            ]))
            elements.append(t_hw)
            elements.append(Spacer(1, 8))
            
            elements.append(Paragraph("Interfaces de Rede", style_cell))
            if_header = [Paragraph("Interface", style_mono), Paragraph("Configuração (IP / MAC)", style_mono)]
            if_rows = [if_header]
            
            if not ifaces:
                if_rows.append(["-", "Nenhuma interface detectada"])
            else:
                for iface in ifaces:
                    iname = iface.get('name', 'eth?') if isinstance(iface, dict) else getattr(iface, 'name', 'eth?')
                    iip = iface.get('ip', iface.get('address', 'N/A')) if isinstance(iface, dict) else getattr(iface, 'ip', 'N/A')
                    imac = iface.get('mac', '') if isinstance(iface, dict) else getattr(iface, 'mac', '')
                    
                    if_rows.append([
                        Paragraph(iname, style_mono),
                        Paragraph(f"IP: {iip}  <font color='grey'>MAC: {imac}</font>", style_mono)
                    ])
            
            t_if = Table(if_rows, colWidths=[120, 400])
            t_if.setStyle(TableStyle([
                ('LINEBELOW', (0,0), (-1,-1), 0.5, COLOR_ACCENT),
                ('BACKGROUND', (0,0), (-1,0), COLOR_BG_HEADER),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            elements.append(t_if)
            elements.append(Spacer(1, 8))

            elements.append(Paragraph("Portas Abertas", style_cell))
            p_header = [Paragraph("Porta/Proto", style_mono), Paragraph("Serviço / Banner", style_mono)]
            p_rows = [p_header]
            
            if not ports:
                p_rows.append(["-", "Nenhuma porta aberta ou scan não realizado"])
            else:
                for p in ports:
                    if isinstance(p, dict):
                        pval = p.get('port', p.get('local_port', '?'))
                        proto = p.get('protocol', 'tcp')
                        svc = p.get('service', p.get('name', 'unknown'))
                        p_str = f"{pval}/{proto}"
                    elif isinstance(p, (list, tuple)):
                        p_str = f"{p[0]}/{p[1]}" if len(p)>1 else str(p[0])
                        svc = "Check-in"
                    else:
                        p_str = str(p)
                        svc = "-"
                        
                    p_rows.append([
                        Paragraph(p_str, style_mono),
                        Paragraph(svc, style_mono_small)
                    ])
                    
            t_ports = Table(p_rows, colWidths=[100, 420])
            t_ports.setStyle(TableStyle([
                ('LINEBELOW', (0,0), (-1,-1), 0.5, COLOR_ACCENT),
                ('BACKGROUND', (0,0), (-1,0), COLOR_BG_HEADER),
            ]))
            elements.append(t_ports)
            
            elements.append(Spacer(1, 15))
            if i < len(machines) - 1:
                elements.append(Paragraph("<hr width='100%' color='#bdc3c7' size='1'/>", styles['Normal']))
                elements.append(Spacer(1, 15))

    doc.build(elements, onFirstPage=header_footer, onLaterPages=header_footer)
    buffer.seek(0)
    return buffer