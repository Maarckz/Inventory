from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime

def generate_pdf_report(stats, machines, include_details=False):
    from io import BytesIO
    buffer = BytesIO()
    
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    elements.append(Paragraph("Relatório de Inventário de TI", styles['Title']))
    elements.append(Paragraph(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
    elements.append(Spacer(1, 24))
    
    elements.append(Paragraph("Estatísticas Gerais", styles['Heading2']))
    stats_data = [
        ["Total de Máquinas", stats['status']['Ativo'] + stats['status']['Inativo']],
        ["Máquinas Ativas", stats['status']['Ativo']],
        ["Máquinas Inativas", stats['status']['Inativo']]
    ]
    stats_table = Table(stats_data)
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 24))
    
    elements.append(Paragraph("Máquinas no Inventário", styles['Heading2']))
    machine_data = [["Hostname", "IP", "Sistema Operacional", "Status"]]
    
    for machine in machines:
        machine_data.append([
            machine['hostname'],
            machine['ip_address'],
            f"{machine['os_name']} {machine['os_version']}",
            machine['device_status']
        ])
    
    machine_table = Table(machine_data)
    machine_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('FONTSIZE', (0,1), (-1,-1), 8)
    ]))
    elements.append(machine_table)
    
    if include_details:
        for machine in machines:
            elements.append(Spacer(1, 24))
            elements.append(Paragraph(f"Detalhes da máquina: {machine['hostname']}", styles['Heading3']))
            
            details_data = [
                ["Hostname", machine['hostname']],
                ["IP Address", machine['ip_address']],
                ["Sistema Operacional", f"{machine['os_name']} {machine['os_version']}"],
                ["Arquitetura", machine['os_architecture']],
                ["Kernel", machine['os_kernel']],
                ["CPU", machine['cpu_name']],
                ["Núcleos", machine['cpu_cores']],
                ["Memória RAM (GB)", machine['ram_total']],
                ["Status", machine['device_status']],
                ["Última Atividade", machine['last_seen']]
            ]
            details_table = Table(details_data, colWidths=[150, 300])
            details_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('GRID', (0,0), (-1,-1), 1, colors.black)
            ]))
            elements.append(details_table)
    
    doc.build(elements)
    buffer.seek(0)
    return buffer