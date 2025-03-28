REPORT_STYLE = """
QDialog {
    background-color: #f5f5f5;
}

QFrame {
    background-color: white;
    border-radius: 8px;
    border: 1px solid #ddd;
}

QLabel {
    color: #2c3e50;
}

QTableWidget {
    background-color: white;
    border: 1px solid #ddd;
    border-radius: 4px;
    gridline-color: #ddd;
}

QTableWidget::item {
    padding: 5px;
}

QTableWidget::item:selected {
    background-color: #3498db;
    color: white;
}

QHeaderView::section {
    background-color: #34495e;
    color: white;
    padding: 5px;
    border: 1px solid #2c3e50;
}

QPushButton {
    background-color: #3498db;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    min-width: 100px;
}

QPushButton:hover {
    background-color: #2980b9;
}

QPushButton:disabled {
    background-color: #bdc3c7;
}

QScrollArea {
    border: none;
}
""" 