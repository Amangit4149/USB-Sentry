class Styles:
    # Modern dark stylesheet with glassmorphic sidebar and vibrant gradients
    MAIN_THEME = """
    /* Main Window */
    QMainWindow {
        background-color: #0b1329;
    }
    
    QWidget {
        color: #f1f5f9;
        font-family: "Segoe UI", Arial, sans-serif;
        font-size: 13px;
    }
    
    /* Left Navigation Sidebar */
    QFrame#sidebar {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #111e38, stop:1 #080f1e);
        border-right: 1px solid #1e293b;
        max-width: 220px;
        min-width: 220px;
    }
    
    QLabel#sidebarHeader {
        font-size: 16px;
        font-weight: bold;
        color: #38bdf8;
        padding: 20px 10px;
        border-bottom: 1px solid #1e293b;
    }
    
    /* Navigation Sidebar Buttons */
    QPushButton#navBtn {
        text-align: left;
        background-color: transparent;
        border: none;
        border-radius: 6px;
        color: #94a3b8;
        padding: 12px 15px;
        font-weight: 500;
        margin: 4px 10px;
    }
    
    QPushButton#navBtn:hover {
        background-color: rgba(56, 189, 248, 0.08);
        color: #f1f5f9;
    }
    
    QPushButton#navBtn:checked {
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0369a1);
        color: #ffffff;
        font-weight: bold;
        border-left: 3px solid #38bdf8;
    }
    
    /* Content Panels */
    QFrame#contentFrame {
        background-color: #0f172a;
        border-top-left-radius: 12px;
        border-bottom-left-radius: 12px;
        margin-top: 10px;
        margin-bottom: 10px;
    }
    
    /* Cards */
    QFrame#card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 15px;
    }
    
    QFrame#alertCard {
        background-color: #1e1b4b;
        border: 1px solid #3730a3;
        border-radius: 8px;
        padding: 15px;
    }
    
    /* Headings */
    QLabel#sectionHeader {
        font-size: 20px;
        font-weight: bold;
        color: #ffffff;
        margin-bottom: 10px;
    }
    
    QLabel#cardHeader {
        font-size: 13px;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    QLabel#cardValue {
        font-size: 24px;
        font-weight: bold;
        color: #38bdf8;
    }
    
    /* Forms & Inputs */
    QLineEdit {
        background-color: #0b1329;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 8px 12px;
        color: #f1f5f9;
        selection-background-color: #0284c7;
    }
    
    QLineEdit:focus {
        border: 1px solid #38bdf8;
    }
    
    QTextEdit {
        background-color: #0b1329;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 8px 12px;
        color: #f1f5f9;
    }
    
    QTextEdit:focus {
        border: 1px solid #38bdf8;
    }
    
    QComboBox {
        background-color: #0b1329;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 8px 12px;
        color: #f1f5f9;
        min-width: 120px;
    }
    
    QComboBox:on {
        border: 1px solid #38bdf8;
    }
    
    QComboBox QAbstractItemView {
        background-color: #0f172a;
        border: 1px solid #334155;
        selection-background-color: #0284c7;
        color: #f1f5f9;
    }
    
    /* Standard Buttons */
    QPushButton#primaryBtn {
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38bdf8, stop:1 #0284c7);
        border: none;
        border-radius: 6px;
        color: #ffffff;
        padding: 8px 16px;
        font-weight: bold;
    }
    
    QPushButton#primaryBtn:hover {
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #7dd3fc, stop:1 #0369a1);
    }
    
    QPushButton#primaryBtn:pressed {
        background-color: #0369a1;
    }
    
    QPushButton#dangerBtn {
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f87171, stop:1 #dc2626);
        border: none;
        border-radius: 6px;
        color: #ffffff;
        padding: 8px 16px;
        font-weight: bold;
    }
    
    QPushButton#dangerBtn:hover {
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fca5a5, stop:1 #b91c1c);
    }
    
    QPushButton#secondaryBtn {
        background-color: #334155;
        border: 1px solid #475569;
        border-radius: 6px;
        color: #f1f5f9;
        padding: 8px 16px;
        font-weight: 500;
    }
    
    QPushButton#secondaryBtn:hover {
        background-color: #475569;
        border-color: #64748b;
    }
    
    /* Data Tables */
    QTableWidget {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        gridline-color: #334155;
        selection-background-color: rgba(56, 189, 248, 0.15);
        selection-color: #38bdf8;
    }
    
    QTableWidget::item {
        padding: 8px;
        border-bottom: 1px solid #334155;
    }
    
    QHeaderView::section {
        background-color: #0f172a;
        color: #e2e8f0;
        padding: 8px;
        border: none;
        border-bottom: 2px solid #334155;
        font-weight: bold;
    }
    
    QScrollBar:vertical {
        border: none;
        background: #0f172a;
        width: 10px;
        margin: 0px;
    }
    
    QScrollBar::handle:vertical {
        background: #334155;
        min-height: 20px;
        border-radius: 5px;
    }
    
    QScrollBar::handle:vertical:hover {
        background: #475569;
    }
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        border: none;
        background: none;
    }
    """

    LOGIN_THEME = """
    QWidget {
        background-color: #0b1329;
        color: #f1f5f9;
        font-family: "Segoe UI", Arial, sans-serif;
    }
    
    QFrame#loginCard {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 30px;
    }
    
    QLabel#logoTitle {
        font-size: 24px;
        font-weight: bold;
        color: #38bdf8;
        margin-bottom: 5px;
    }
    
    QLabel#logoSubtitle {
        font-size: 12px;
        color: #94a3b8;
        margin-bottom: 25px;
    }
    
    QLineEdit {
        background-color: #0b1329;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 10px 15px;
        color: #f1f5f9;
        font-size: 14px;
    }
    
    QLineEdit:focus {
        border: 1px solid #38bdf8;
    }
    
    QPushButton#loginBtn {
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38bdf8, stop:1 #0284c7);
        border: none;
        border-radius: 6px;
        color: #ffffff;
        padding: 12px;
        font-weight: bold;
        font-size: 14px;
        margin-top: 10px;
    }
    
    QPushButton#loginBtn:hover {
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #7dd3fc, stop:1 #0369a1);
    }
    """
