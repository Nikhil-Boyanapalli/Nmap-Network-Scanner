from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QScrollArea, QWidget, QPushButton, QTableWidget, 
                            QTableWidgetItem, QFrame, QTabWidget)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from styles import REPORT_STYLE

class ReportViewer(QDialog):
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.scan_results = scan_results
        self.setStyleSheet(REPORT_STYLE)
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Scan Report")
        self.setMinimumSize(900, 700)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Create a tab widget
        tab_widget = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        self.setup_overview_tab(overview_layout)
        tab_widget.addTab(overview_tab, "Overview")
        
        # Vulnerabilities tab
        vuln_tab = QWidget()
        vuln_layout = QVBoxLayout(vuln_tab)
        self.setup_vulnerabilities_tab(vuln_layout)
        tab_widget.addTab(vuln_tab, "Vulnerabilities")
        
        # Services tab
        services_tab = QWidget()
        services_layout = QVBoxLayout(services_tab)
        self.setup_services_tab(services_layout)
        tab_widget.addTab(services_tab, "Services")
        
        layout.addWidget(tab_widget)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)

    def setup_overview_tab(self, layout):
        # Title
        title = QLabel("Network Security Scan Report")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Scan Information Section
        scan_info_frame = QFrame()
        scan_info_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        scan_info_layout = QVBoxLayout(scan_info_frame)
        
        scan_info_title = QLabel("Scan Information")
        scan_info_title.setFont(QFont("", 12, QFont.Weight.Bold))
        scan_info_layout.addWidget(scan_info_title)
        
        # Scan details
        scan_details = QTableWidget()
        scan_details.setColumnCount(2)
        scan_details.setRowCount(4)
        scan_details.setHorizontalHeaderLabels(["Property", "Value"])
        scan_details.verticalHeader().setVisible(False)
        
        details = [
            ("Target", self.scan_results['target']),
            ("Scan Type", self.scan_results['scan_type']),
            ("Start Time", self.scan_results['scan_start_time']),
            ("End Time", self.scan_results['scan_end_time'])
        ]
        
        for row, (prop, value) in enumerate(details):
            scan_details.setItem(row, 0, QTableWidgetItem(prop))
            scan_details.setItem(row, 1, QTableWidgetItem(str(value)))
        
        scan_details.resizeColumnsToContents()
        scan_info_layout.addWidget(scan_details)
        layout.addWidget(scan_info_frame)

        # Summary section
        summary_frame = QFrame()
        summary_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        summary_layout = QVBoxLayout(summary_frame)
        
        summary_title = QLabel("Scan Summary")
        summary_title.setFont(QFont("", 12, QFont.Weight.Bold))
        summary_layout.addWidget(summary_title)
        
        total_hosts = len(self.scan_results['hosts'])
        active_hosts = sum(1 for host in self.scan_results['hosts'] if host['state'] == 'up')
        total_vulns = sum(len(host.get('vulnerabilities', [])) for host in self.scan_results['hosts'])
        critical_vulns = sum(
            sum(1 for vuln in host.get('vulnerabilities', []) if vuln['risk_level'] == 'Critical')
            for host in self.scan_results['hosts']
        )
        
        summary_text = f"""
        <p>Total Hosts Scanned: {total_hosts}</p>
        <p>Active Hosts: {active_hosts}</p>
        <p>Total Vulnerabilities Found: {total_vulns}</p>
        <p>Critical Vulnerabilities: {critical_vulns}</p>
        """
        
        summary_label = QLabel(summary_text)
        summary_layout.addWidget(summary_label)
        layout.addWidget(summary_frame)

    def setup_vulnerabilities_tab(self, layout):
        # Create table for vulnerabilities
        vuln_table = QTableWidget()
        vuln_table.setColumnCount(6)
        vuln_table.setHorizontalHeaderLabels([
            "Host", "Vulnerability", "Risk Level", "CVE IDs", 
            "Description", "Recommendation"
        ])
        
        # Collect all vulnerabilities
        all_vulns = []
        for host in self.scan_results['hosts']:
            for vuln in host.get('vulnerabilities', []):
                all_vulns.append((host['ip'], vuln))
        
        vuln_table.setRowCount(len(all_vulns))
        
        for row, (host_ip, vuln) in enumerate(all_vulns):
            # Host IP
            vuln_table.setItem(row, 0, QTableWidgetItem(host_ip))
            
            # Vulnerability Name
            vuln_table.setItem(row, 1, QTableWidgetItem(vuln['name']))
            
            # Risk Level
            risk_item = QTableWidgetItem(vuln['risk_level'])
            if vuln['risk_level'] == 'Critical':
                risk_item.setBackground(QColor('#ffcccc'))
            elif vuln['risk_level'] == 'High':
                risk_item.setBackground(QColor('#ffdccc'))
            vuln_table.setItem(row, 2, risk_item)
            
            # CVE IDs
            vuln_table.setItem(row, 3, QTableWidgetItem(', '.join(vuln['cve_ids'])))
            
            # Description
            vuln_table.setItem(row, 4, QTableWidgetItem(vuln['description']))
            
            # Recommendation
            vuln_table.setItem(row, 5, QTableWidgetItem(vuln['recommendation']))
        
        vuln_table.resizeColumnsToContents()
        layout.addWidget(vuln_table)

    def setup_services_tab(self, layout):
        # Create table for services
        services_table = QTableWidget()
        services_table.setColumnCount(6)
        services_table.setHorizontalHeaderLabels([
            "Host", "Port", "State", "Service", "Version", "Additional Info"
        ])
        
        # Collect all services
        all_services = []
        for host in self.scan_results['hosts']:
            for port in host['ports']:
                if port['state'] == 'open':
                    all_services.append((host['ip'], port))
        
        services_table.setRowCount(len(all_services))
        
        for row, (host_ip, port) in enumerate(all_services):
            services_table.setItem(row, 0, QTableWidgetItem(host_ip))
            services_table.setItem(row, 1, QTableWidgetItem(str(port['port'])))
            services_table.setItem(row, 2, QTableWidgetItem(port['state']))
            services_table.setItem(row, 3, QTableWidgetItem(port['service']))
            version_info = f"{port['product']} {port['version']}".strip()
            services_table.setItem(row, 4, QTableWidgetItem(version_info))
            services_table.setItem(row, 5, QTableWidgetItem(port['extrainfo']))
        
        services_table.resizeColumnsToContents()
        layout.addWidget(services_table) 