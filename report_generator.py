from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
import os
import logging

class ReportGenerator:
    def __init__(self):
        self.reports_dir = "reports"
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def generate_pdf(self, scan_results):
        """
        Generate a PDF report from scan results
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.reports_dir, f"scan_report_{timestamp}.pdf")
            
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []

            # Title
            title_style = styles['Heading1']
            title_style.fontSize = 24
            title_style.spaceAfter = 30
            elements.append(Paragraph("Network Security Scan Report", title_style))

            # Scan Information
            elements.append(Paragraph("Scan Information", styles['Heading2']))
            scan_info = [
                ["Target:", scan_results['target']],
                ["Scan Type:", scan_results['scan_type']],
                ["Start Time:", scan_results['scan_start_time']],
                ["End Time:", scan_results['scan_end_time']]
            ]
            
            scan_table = Table(scan_info, colWidths=[100, 300])
            scan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(scan_table)
            elements.append(Spacer(1, 20))

            # Host Information
            elements.append(Paragraph("Host Information", styles['Heading2']))
            
            for host in scan_results['hosts']:
                elements.append(Paragraph(f"Host: {host['ip']}", styles['Heading3']))
                elements.append(Paragraph(f"State: {host['state']}", styles['Normal']))
                
                if 'os' in host:
                    elements.append(Paragraph(f"Operating System: {host['os']}", styles['Normal']))
                
                if host['ports']:
                    open_ports = [p for p in host['ports'] if p['state'] == 'open']
                    if open_ports:
                        elements.append(Paragraph("Open Ports and Services:", styles['Heading4']))
                        port_data = [['Port', 'State', 'Service', 'Version']]
                        for port in open_ports:
                            port_data.append([
                                str(port['port']),
                                port['state'],
                                port['service'],
                                port['version']
                            ])
                        
                        port_table = Table(port_data, colWidths=[50, 70, 100, 150])
                        port_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTSIZE', (0, 0), (-1, 0), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                            ('FONTSIZE', (0, 1), (-1, -1), 9),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        elements.append(port_table)
                
                elements.append(Spacer(1, 20))

            # Build the PDF
            doc.build(elements)
            return filename
        except Exception as e:
            logging.error(f"Error generating PDF: {str(e)}")
            raise Exception("Failed to generate PDF report. Please check the logs for details.")

    def generate_html(self, scan_results):
        """
        Generate an HTML report from scan results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.reports_dir, f"scan_report_{timestamp}.html")
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Scan Report</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 40px; 
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                h1 { 
                    color: #2c3e50; 
                    text-align: center;
                    padding-bottom: 20px;
                    border-bottom: 2px solid #eee;
                }
                h2 { 
                    color: #34495e;
                    margin-top: 30px;
                }
                h3 { 
                    color: #7f8c8d; 
                }
                table { 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin: 20px 0;
                    background-color: white;
                }
                th, td { 
                    border: 1px solid #ddd; 
                    padding: 12px; 
                    text-align: left; 
                }
                th { 
                    background-color: #f5f5f5; 
                }
                .port-table th { 
                    background-color: #2c3e50; 
                    color: white; 
                }
                .host-info {
                    background-color: white;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 4px;
                    border: 1px solid #ddd;
                }
                .service-list {
                    list-style-type: none;
                    padding-left: 20px;
                }
                .service-list li {
                    margin: 8px 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Network Security Scan Report</h1>
                
                <h2>Scan Information</h2>
                <table>
                    <tr><th>Target</th><td>{target}</td></tr>
                    <tr><th>Scan Type</th><td>{scan_type}</td></tr>
                    <tr><th>Start Time</th><td>{start_time}</td></tr>
                    <tr><th>End Time</th><td>{end_time}</td></tr>
                </table>

                <h2>Host Information</h2>
        """.format(
            target=scan_results['target'],
            scan_type=scan_results['scan_type'],
            start_time=scan_results['scan_start_time'],
            end_time=scan_results['scan_end_time']
        )

        for host in scan_results['hosts']:
            html_content += f"""
            <div class="host-info">
                <h3>Host: {host['ip']}</h3>
                <p>State: {host['state']}</p>
            """
            
            if 'os' in host:
                html_content += f"<p>Operating System: {host['os']}</p>"
            
            if host['ports']:
                open_ports = [p for p in host['ports'] if p['state'] == 'open']
                if open_ports:
                    html_content += """
                    <h4>Open Services:</h4>
                    <ul class="service-list">
                    """
                    
                    for port in open_ports:
                        version_info = f" - {port['version']}" if port['version'] != 'unknown' else ''
                        html_content += f"""
                        <li>
                            <strong>{port['service']}</strong> (Port {port['port']})
                            {version_info}
                        </li>
                        """
                    
                    html_content += "</ul>"
            
            html_content += "</div>"

        html_content += """
            </div>
        </body>
        </html>
        """

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename 