from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTextBrowser, QPushButton, QDialogButtonBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QDesktopServices
from PyQt6.QtCore import QUrl

class WelcomeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to Network Scanner")
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout()
        
        # Welcome message
        welcome_label = QLabel("Welcome to Network Scanner!")
        welcome_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(welcome_label)
        
        # Instructions text browser
        self.instructions = QTextBrowser()
        self.instructions.setOpenExternalLinks(True)
        self.instructions.setMinimumHeight(200)
        
        instructions_text = """
        <h3>Important: Nmap Installation Required</h3>
        <p>This application requires Nmap to perform network scanning. If you haven't installed Nmap yet, please follow these instructions:</p>
        
        <h4>Windows:</h4>
        <ol>
            <li>Download Nmap from <a href="https://nmap.org/download.html">https://nmap.org/download.html</a></li>
            <li>Download the latest stable release Windows installer (e.g., "nmap-7.94-setup.exe")</li>
            <li>Run the installer with administrator privileges</li>
            <li>Make sure to select the option to "Add Nmap to PATH" during installation</li>
        </ol>
        
        <h4>Linux:</h4>
        <p>Open terminal and run:</p>
        <pre>sudo apt-get install nmap</pre>
        <p>Or for RPM-based distributions:</p>
        <pre>sudo yum install nmap</pre>
        
        <h4>macOS:</h4>
        <p>Using Homebrew:</p>
        <pre>brew install nmap</pre>
        
        <p>After installation, you may need to restart your computer for the changes to take effect.</p>
        """
        self.instructions.setHtml(instructions_text)
        layout.addWidget(self.instructions)
        
        # Buttons
        button_box = QDialogButtonBox()
        self.install_button = QPushButton("Install Nmap")
        self.install_button.clicked.connect(self.open_nmap_website)
        self.skip_button = QPushButton("Skip (I already have Nmap)")
        
        button_box.addButton(self.install_button, QDialogButtonBox.ButtonRole.ActionRole)
        button_box.addButton(self.skip_button, QDialogButtonBox.ButtonRole.AcceptRole)
        
        layout.addWidget(button_box)
        self.setLayout(layout)
        
        # Connect buttons
        self.skip_button.clicked.connect(self.accept)
    
    def open_nmap_website(self):
        QDesktopServices.openUrl(QUrl("https://nmap.org/download.html")) 