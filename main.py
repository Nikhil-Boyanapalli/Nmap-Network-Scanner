import sys
import traceback
import logging
import os.path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                           QPushButton, QTextEdit, QProgressBar, QMessageBox,
                           QLabel, QDialog, QDialogButtonBox, QTextBrowser,
                           QHBoxLayout, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from scanner import NetworkScanner
from welcome_dialog import WelcomeDialog
from report_viewer import ReportViewer
from datetime import datetime
import nmap

# Set up logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s',
                   filename='network_scanner.log')

class NmapScannerThread(QThread):
    scan_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    status_update = pyqtSignal(str)

    def __init__(self, scan_type):
        super().__init__()
        self.scan_type = scan_type
        self.network_scanner = NetworkScanner()

    def run(self):
        try:
            # Get network range automatically
            self.status_update.emit("Detecting network...")
            target = self.network_scanner.get_network_range()
            self.status_update.emit(f"Scanning network: {target}")

            # Initialize Nmap scanner
            nm = nmap.PortScanner()
            args = '-sn' if self.scan_type == 'Host Discovery' else '-sV'
            nm.scan(target, arguments=args)
            
            results = []
            for host in nm.all_hosts():
                host_info = {
                    'ip': host,
                    'state': nm[host].state(),
                    'ports': []
                }
                
                if 'osmatch' in nm[host]:
                    host_info['os'] = nm[host]['osmatch'][0]['name'] if nm[host]['osmatch'] else 'Unknown'
                
                if self.scan_type != 'Host Discovery':
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            port_info = nm[host][proto][port]
                            host_info['ports'].append({
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info['name'],
                                'version': port_info['version'] if 'version' in port_info else 'unknown'
                            })
                
                results.append(host_info)
                self.status_update.emit(f"Found device: {host}")
            
            self.scan_complete.emit({'hosts': results, 'target': target})
        except Exception as e:
            self.error_occurred.emit(str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner")
        self.setMinimumSize(800, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                padding: 5px;
                font-family: Consolas, Monaco, monospace;
            }
        """)
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title_label = QLabel("Network Scanner")
        title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        # Description
        desc_label = QLabel("Click 'Start Scan' to automatically scan your network for devices and security issues.")
        desc_label.setFont(QFont("Arial", 12))
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        # Scan type combo box in its own layout
        scan_type_layout = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Host Discovery", "Quick Service Scan", "Full Service Scan"])
        scan_type_layout.addWidget(scan_type_label)
        scan_type_layout.addWidget(self.scan_type_combo)
        scan_type_layout.addStretch()
        layout.addLayout(scan_type_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        # Buttons layout
        button_layout = QHBoxLayout()
        
        # Start button
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        self.start_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        button_layout.addWidget(self.start_button)

        # View Report button
        self.view_report_btn = QPushButton("View Report")
        self.view_report_btn.setEnabled(False)
        self.view_report_btn.clicked.connect(self.show_report)
        button_layout.addWidget(self.view_report_btn)

        layout.addLayout(button_layout)

        # Results area
        self.results_area = QLabel("Scan results will appear here")
        self.results_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_area.setStyleSheet("QLabel { background-color: white; padding: 10px; border: 1px solid #ccc; }")
        layout.addWidget(self.results_area)

        self.scan_results = None
        self.scan_start_time = None
        logging.info("MainWindow initialized successfully")

    def check_first_run(self):
        if not os.path.exists(".firstrun"):
            welcome = WelcomeDialog(self)
            welcome.exec()
            with open(".firstrun", "w") as f:
                f.write("1")

    def start_scan(self):
        # Store scan start time
        self.scan_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Disable controls during scan
        self.start_button.setEnabled(False)
        self.scan_type_combo.setEnabled(False)
        self.view_report_btn.setEnabled(False)
        
        # Reset and show progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(0)
        self.progress_bar.setValue(0)
        
        # Clear previous status and results
        self.status_label.setText("Initializing scan...")
        self.results_area.setText("")
        
        # Start the scan
        self.scanner_thread = NmapScannerThread(self.scan_type_combo.currentText())
        self.scanner_thread.scan_complete.connect(self.scan_completed)
        self.scanner_thread.error_occurred.connect(self.handle_error)
        self.scanner_thread.status_update.connect(self.update_status)
        self.scanner_thread.start()

    def update_status(self, message):
        self.status_label.setText(message)

    def scan_completed(self, results):
        self.progress_bar.setVisible(False)
        self.start_button.setEnabled(True)
        self.scan_type_combo.setEnabled(True)
        
        # Store scan results
        self.scan_results = {
            'target': results['target'],
            'scan_type': self.scan_type_combo.currentText(),
            'scan_start_time': self.scan_start_time,
            'scan_end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'hosts': results['hosts']
        }
        
        # Update results display
        self.display_results(results['hosts'])
        
        # Enable report button
        self.view_report_btn.setEnabled(True)
        self.status_label.setText("Scan completed successfully!")
        QMessageBox.information(self, "Scan Complete", "Network scan has been completed successfully!")

    def handle_error(self, error_message):
        self.progress_bar.setVisible(False)
        self.start_button.setEnabled(True)
        self.scan_type_combo.setEnabled(True)
        self.status_label.setText(f"Error: {error_message}")
        QMessageBox.critical(self, "Error", f"Scan failed: {error_message}")

    def display_results(self, hosts):
        result_text = "<h3>Scan Results:</h3>"
        for host in hosts:
            result_text += f"<p><b>Host:</b> {host['ip']} ({host['state']})</p>"
            if 'os' in host:
                result_text += f"<p><b>OS:</b> {host['os']}</p>"
            if host['ports']:
                result_text += "<p><b>Open Ports:</b></p><ul>"
                for port in host['ports']:
                    if port['state'] == 'open':
                        result_text += f"<li>Port {port['port']}: {port['service']} ({port['version']})</li>"
                result_text += "</ul>"
        
        self.results_area.setText(result_text)

    def show_report(self):
        if self.scan_results:
            report_dialog = ReportViewer(self.scan_results, self)
            report_dialog.exec()

if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        
        # Show welcome dialog on first run
        settings_file = "app_settings.txt"
        if not os.path.exists(settings_file):
            window.check_first_run()
            # Create settings file to mark first run complete
            with open(settings_file, "w") as f:
                f.write("first_run_complete=true")
        
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        logging.critical(f"Application crashed: {str(e)}\n{traceback.format_exc()}")
        print(f"Critical error: {str(e)}")
        sys.exit(1) 