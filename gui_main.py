#!/usr/bin/env python3
"""
Antivirus Prototype - GUI Version
"""

import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QVBoxLayout, 
                           QWidget, QPushButton, QTextEdit, QListWidget, QLabel,
                           QProgressBar, QMessageBox, QFileDialog, QHBoxLayout)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont, QIcon

# Add src to path
sys.path.append('src')
sys.path.append('gui')

from src.scanner import VirusScanner
from src.quarantine import QuarantineManager
from src.network_monitor import NetworkMonitor
from src.system_monitor import SystemMonitor
from src.ransomware_detector import RansomwareDetector

class AntivirusGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner = VirusScanner()
        self.quarantine_manager = QuarantineManager()
        self.network_monitor = NetworkMonitor()
        self.system_monitor = SystemMonitor()
        self.ransomware_detector = RansomwareDetector()
        
        self.is_monitoring = False
        self.init_ui()
        self.setup_monitors()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle('Antivirus Prototype - Security Dashboard')
        self.setGeometry(100, 100, 900, 700)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_file_scan_tab()
        self.create_network_monitor_tab()
        self.create_system_monitor_tab()
        self.create_quarantine_tab()
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.statusBar().addWidget(self.status_label)
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_monitoring_data)
        self.update_timer.start(2000)  # Update every 2 seconds
        
    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)
        
        # Title
        title = QLabel("Security Dashboard")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Security status
        self.security_status = QLabel("🔒 Security Status: Protected")
        self.security_status.setFont(QFont("Arial", 14))
        layout.addWidget(self.security_status)
        
        # Quick actions
        quick_actions_layout = QHBoxLayout()
        
        scan_btn = QPushButton("Quick Scan")
        scan_btn.clicked.connect(self.quick_scan)
        quick_actions_layout.addWidget(scan_btn)
        
        monitor_btn = QPushButton("Start Monitoring")
        monitor_btn.clicked.connect(self.toggle_monitoring)
        quick_actions_layout.addWidget(monitor_btn)
        
        layout.addLayout(quick_actions_layout)
        
        # Alerts display
        self.alerts_display = QTextEdit()
        self.alerts_display.setReadOnly(True)
        self.alerts_display.setPlaceholderText("Security alerts will appear here...")
        layout.addWidget(self.alerts_display)
        
        self.tabs.addTab(dashboard_widget, "Dashboard")
        
    def create_file_scan_tab(self):
        """Create the file scanning tab"""
        scan_widget = QWidget()
        layout = QVBoxLayout(scan_widget)
        
        # Scan controls
        controls_layout = QHBoxLayout()
        
        select_file_btn = QPushButton("Select File")
        select_file_btn.clicked.connect(self.select_file)
        controls_layout.addWidget(select_file_btn)
        
        select_folder_btn = QPushButton("Select Folder")
        select_folder_btn.clicked.connect(self.select_folder)
        controls_layout.addWidget(select_folder_btn)
        
        scan_btn = QPushButton("Start Scan")
        scan_btn.clicked.connect(self.start_scan)
        controls_layout.addWidget(scan_btn)
        
        quarantine_btn = QPushButton("Quarantine Selected")
        quarantine_btn.clicked.connect(self.quarantine_selected)
        controls_layout.addWidget(quarantine_btn)
        
        layout.addLayout(controls_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        layout.addWidget(self.results_display)
        
        # Infected files list
        self.infected_files_list = QListWidget()
        layout.addWidget(QLabel("Infected Files:"))
        layout.addWidget(self.infected_files_list)
        
        self.tabs.addTab(scan_widget, "File Scanner")
        
    def create_network_monitor_tab(self):
        """Create network monitoring tab"""
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        self.network_alerts = QTextEdit()
        self.network_alerts.setReadOnly(True)
        layout.addWidget(QLabel("Network Alerts:"))
        layout.addWidget(self.network_alerts)
        
        self.tabs.addTab(network_widget, "Network Monitor")
        
    def create_system_monitor_tab(self):
        """Create system monitoring tab"""
        system_widget = QWidget()
        layout = QVBoxLayout(system_widget)
        
        self.system_alerts = QTextEdit()
        self.system_alerts.setReadOnly(True)
        layout.addWidget(QLabel("System Alerts:"))
        layout.addWidget(self.system_alerts)
        
        self.tabs.addTab(system_widget, "System Monitor")
        
    def create_quarantine_tab(self):
        """Create quarantine management tab"""
        quarantine_widget = QWidget()
        layout = QVBoxLayout(quarantine_widget)
        
        # Quarantine controls
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_quarantine)
        controls_layout.addWidget(refresh_btn)
        
        restore_btn = QPushButton("Restore Selected")
        restore_btn.clicked.connect(self.restore_quarantined)
        controls_layout.addWidget(restore_btn)
        
        layout.addLayout(controls_layout)
        
        # Quarantined files list
        self.quarantine_list = QListWidget()
        layout.addWidget(self.quarantine_list)
        
        self.tabs.addTab(quarantine_widget, "Quarantine")
        
    def setup_monitors(self):
        """Setup monitoring systems"""
        # Network monitor will be started when monitoring begins
        pass
        
    def toggle_monitoring(self):
        """Toggle all monitoring systems"""
        if not self.is_monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
            
    def start_monitoring(self):
        """Start all monitoring systems"""
        self.network_monitor.start_monitoring()
        self.system_monitor.start_monitoring()
        self.ransomware_detector.start_monitoring()
        self.is_monitoring = True
        self.status_label.setText("Monitoring: ACTIVE")
        self.security_status.setText("🔒 Security Status: Active Monitoring")
        QMessageBox.information(self, "Monitoring Started", 
                               "All security monitoring systems are now active.")
        
    def stop_monitoring(self):
        """Stop all monitoring systems"""
        self.network_monitor.stop_monitoring()
        self.system_monitor.stop_monitoring()
        self.ransomware_detector.stop_monitoring()
        self.is_monitoring = False
        self.status_label.setText("Monitoring: INACTIVE")
        self.security_status.setText("🔒 Security Status: Basic Protection")
        QMessageBox.information(self, "Monitoring Stopped", 
                               "Security monitoring systems have been stopped.")
        
    def update_monitoring_data(self):
        """Update monitoring data displays"""
        if self.is_monitoring:
            # Update network alerts
            network_alerts = self.network_monitor.get_network_alerts()
            self.network_alerts.clear()
            for alert in network_alerts[-10:]:  # Show last 10 alerts
                self.network_alerts.append(f"{alert['type']}: {alert.get('local_address', 'N/A')}")
                
            # Update system alerts
            system_alerts = self.system_monitor.get_system_alerts()
            self.system_alerts.clear()
            for alert in system_alerts[-10:]:
                self.system_alerts.append(f"{alert['type']}: {alert.get('process_name', 'N/A')}")
                
            # Update dashboard
            self.update_dashboard_alerts()
            
    def update_dashboard_alerts(self):
        """Update dashboard with recent alerts"""
        all_alerts = []
        all_alerts.extend(self.network_monitor.get_network_alerts()[-5:])
        all_alerts.extend(self.system_monitor.get_system_alerts()[-5:])
        all_alerts.extend(self.ransomware_detector.get_ransomware_alerts()[-5:])
        
        # Sort by timestamp
        all_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        self.alerts_display.clear()
        for alert in all_alerts[:10]:  # Show 10 most recent
            self.alerts_display.append(f"⚠️ {alert['type']} - {alert.get('process_name', alert.get('local_address', 'Alert'))}")
        
    def select_file(self):
        """Select file for scanning"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if file_path:
            self.scan_target = file_path
            self.status_label.setText(f"Selected: {file_path}")
            
    def select_folder(self):
        """Select folder for scanning"""
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder_path:
            self.scan_target = folder_path
            self.status_label.setText(f"Selected: {folder_path}")
            
    def start_scan(self):
        """Start file scanning"""
        if hasattr(self, 'scan_target'):
            self.results_display.clear()
            self.infected_files_list.clear()
            self.progress_bar.setValue(0)
            
            # Simulate progress
            self.progress_timer = QTimer()
            self.progress_timer.timeout.connect(self.update_progress)
            self.progress_timer.start(100)
            
            # Perform scan (in real app, this would be in a thread)
            if os.path.isfile(self.scan_target):
                results = [self.scanner.scan_file(self.scan_target)]
            else:
                results = self.scanner.scan_directory(self.scan_target)
                
            self.display_scan_results(results)
            self.progress_bar.setValue(100)
            self.progress_timer.stop()
            
    def update_progress(self):
        """Update progress bar during scan"""
        current_value = self.progress_bar.value()
        if current_value < 90:
            self.progress_bar.setValue(current_value + 10)
            
    def display_scan_results(self, results):
        """Display scan results"""
        infected_count = 0
        
        for result in results:
            status_icon = "✅" if result["status"] == "CLEAN" else "❌"
            self.results_display.append(f"{status_icon} {result['file']} - {result['status']}")
            
            if result["status"] == "INFECTED":
                infected_count += 1
                self.infected_files_list.addItem(result['file'])
                
        summary = self.scanner.get_scan_summary()
        self.results_display.append(f"\n📊 Scan Summary:")
        self.results_display.append(f"Total files: {summary['total_files']}")
        self.results_display.append(f"Infected: {summary['infected_files']}")
        self.results_display.append(f"Clean: {summary['clean_files']}")
        
        self.status_label.setText(f"Scan complete: {infected_count} threats found")
        
    def quarantine_selected(self):
        """Quarantine selected infected files"""
        selected_items = self.infected_files_list.selectedItems()
        for item in selected_items:
            file_path = item.text()
            if self.quarantine_manager.quarantine_file(file_path):
                self.results_display.append(f"✅ Quarantined: {file_path}")
            else:
                self.results_display.append(f"❌ Failed to quarantine: {file_path}")
                
    def refresh_quarantine(self):
        """Refresh quarantine list"""
        self.quarantine_list.clear()
        quarantined_files = self.quarantine_manager.get_quarantined_files()
        for file in quarantined_files:
            self.quarantine_list.addItem(file)
            
    def restore_quarantined(self):
        """Restore selected quarantined file"""
        selected_items = self.quarantine_list.selectedItems()
        if selected_items:
            file_name = selected_items[0].text()
            # In real implementation, you'd ask for restore location
            QMessageBox.information(self, "Restore", 
                                  f"Would restore {file_name} in real implementation")
            
    def quick_scan(self):
        """Perform quick scan of common directories"""
        common_dirs = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]
        self.results_display.clear()
        self.results_display.append("🚀 Starting quick scan...")
        
        total_infected = 0
        for directory in common_dirs:
            if os.path.exists(directory):
                results = self.scanner.scan_directory(directory)
                infected = len([r for r in results if r["status"] == "INFECTED"])
                total_infected += infected
                self.results_display.append(f"Scanned {directory}: {infected} threats")
                
        self.results_display.append(f"\n✅ Quick scan complete: {total_infected} total threats found")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Antivirus Prototype")
    
    window = AntivirusGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()