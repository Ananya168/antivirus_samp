#!/usr/bin/env python3
"""
Complete Antivirus GUI with All Features
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import socket

# Add src to path
sys.path.append('src')

from src.scanner import VirusScanner
from src.quarantine import QuarantineManager
from src.network_monitor import NetworkMonitor
from src.file_monitor import RealTimeFileMonitor
from src.firewall import SimpleFirewall
from src.web_shield import WebShield
from src.vulnerability_scanner import VulnerabilityScanner

class CompleteAntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Complete Antivirus Suite")
        self.root.geometry("1000x800")
        
        # Initialize all components
        self.scanner = VirusScanner()
        self.quarantine_manager = QuarantineManager()
        self.network_monitor = NetworkMonitor()
        self.file_monitor = RealTimeFileMonitor(self.scanner)
        self.firewall = SimpleFirewall()
        self.web_shield = WebShield()
        self.vulnerability_scanner = VulnerabilityScanner()
        
        self.network_monitoring = False
        self.realtime_monitoring = False
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface with all tabs"""
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create all tabs
        self.setup_dashboard_tab()
        self.setup_scanner_tab()
        self.setup_realtime_tab()
        self.setup_network_tab()
        self.setup_firewall_tab()
        self.setup_web_protection_tab()
        self.setup_vulnerability_tab()
        self.setup_quarantine_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Complete Antivirus Suite")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief='sunken')
        status_bar.pack(side='bottom', fill='x')
        
        # Start background updates
        self.setup_background_updates()
        
    def setup_dashboard_tab(self):
        """Setup the dashboard tab"""
        dashboard = ttk.Frame(self.notebook)
        self.notebook.add(dashboard, text="Dashboard")
        
        # Title
        title = ttk.Label(dashboard, text="🛡️ Antivirus Security Dashboard", 
                         font=('Arial', 16, 'bold'))
        title.pack(pady=10)
        
        # Security status frame
        status_frame = ttk.LabelFrame(dashboard, text="Security Status")
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.security_status = ttk.Label(status_frame, text="🔒 All Systems Operational", 
                                       font=('Arial', 12))
        self.security_status.pack(pady=10)
        
        # Quick actions
        actions_frame = ttk.LabelFrame(dashboard, text="Quick Actions")
        actions_frame.pack(fill='x', padx=10, pady=5)
        
        action_buttons = ttk.Frame(actions_frame)
        action_buttons.pack(pady=10)
        
        ttk.Button(action_buttons, text="Quick Scan", 
                  command=self.quick_scan).pack(side='left', padx=5)
        ttk.Button(action_buttons, text="Vulnerability Scan", 
                  command=self.quick_vulnerability_scan).pack(side='left', padx=5)
        ttk.Button(action_buttons, text="Network Scan", 
                  command=self.quick_network_scan).pack(side='left', padx=5)
        
        # Recent alerts
        alerts_frame = ttk.LabelFrame(dashboard, text="Recent Alerts")
        alerts_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.dashboard_alerts = scrolledtext.ScrolledText(alerts_frame, height=15)
        self.dashboard_alerts.pack(fill='both', expand=True, padx=5, pady=5)
        self.dashboard_alerts.insert(tk.END, "No recent alerts. System is secure.\n")
        
    def setup_scanner_tab(self):
        """Setup the file scanner tab"""
        self.scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_frame, text="File Scanner")
        
        # File selection
        file_frame = ttk.LabelFrame(self.scanner_frame, text="File Selection")
        file_frame.pack(fill='x', padx=5, pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=50).pack(side='left', padx=5, pady=5)
        
        ttk.Button(file_frame, text="Browse File", command=self.browse_file).pack(side='left', padx=5)
        ttk.Button(file_frame, text="Browse Folder", command=self.browse_folder).pack(side='left', padx=5)
        
        # Scan controls
        control_frame = ttk.Frame(self.scanner_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(control_frame, text="Start Scan", command=self.start_scan).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Quick Scan", command=self.quick_scan).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Clear Results", command=self.clear_results).pack(side='left', padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.scanner_frame, mode='determinate')
        self.progress.pack(fill='x', padx=5, pady=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.scanner_frame, text="Scan Results")
        results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15)
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def setup_realtime_tab(self):
        """Setup real-time protection tab"""
        realtime_widget = ttk.Frame(self.notebook)
        self.notebook.add(realtime_widget, text="Real-Time Protection")
        
        # Real-time monitoring controls
        monitor_frame = ttk.LabelFrame(realtime_widget, text="Real-Time File Monitoring")
        monitor_frame.pack(fill='x', padx=5, pady=5)
        
        self.realtime_btn = ttk.Button(monitor_frame, text="Start Real-Time Monitoring", 
                                      command=self.toggle_realtime_monitoring)
        self.realtime_btn.pack(padx=5, pady=5)
        
        # Monitored directories
        dirs_frame = ttk.LabelFrame(realtime_widget, text="Monitored Directories")
        dirs_frame.pack(fill='x', padx=5, pady=5)
        
        dirs_text = scrolledtext.ScrolledText(dirs_frame, height=3)
        dirs_text.pack(fill='x', padx=5, pady=5)
        for directory in self.file_monitor.monitored_dirs:
            dirs_text.insert(tk.END, f"• {directory}\n")
        dirs_text.config(state='disabled')
        
        # Real-time alerts
        alerts_frame = ttk.LabelFrame(realtime_widget, text="Real-Time Alerts")
        alerts_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.realtime_alerts = scrolledtext.ScrolledText(alerts_frame, height=10)
        self.realtime_alerts.pack(fill='both', expand=True, padx=5, pady=5)
        
    def setup_network_tab(self):
        """Setup the network monitor tab"""
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="Network Monitor")
        
        # Network Info
        info_frame = ttk.LabelFrame(self.network_frame, text="Network Information")
        info_frame.pack(fill='x', padx=5, pady=5)
        
        self.network_info_text = scrolledtext.ScrolledText(info_frame, height=4)
        self.network_info_text.pack(fill='x', padx=5, pady=5)
        
        # Network Controls
        control_frame = ttk.Frame(self.network_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(control_frame, text="Get Network Info", 
                  command=self.get_network_info).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Scan Connections", 
                  command=self.scan_connections).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Port Scan", 
                  command=self.port_scan).pack(side='left', padx=5)
        
        # Monitor Controls
        monitor_frame = ttk.Frame(self.network_frame)
        monitor_frame.pack(fill='x', padx=5, pady=5)
        
        self.monitor_btn = ttk.Button(monitor_frame, text="Start Monitoring", 
                                     command=self.toggle_network_monitoring)
        self.monitor_btn.pack(side='left', padx=5)
        
        ttk.Button(monitor_frame, text="Clear Log", 
                  command=self.clear_network_log).pack(side='left', padx=5)
        
        # Network Alerts
        alerts_frame = ttk.LabelFrame(self.network_frame, text="Network Alerts")
        alerts_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.network_alerts_text = scrolledtext.ScrolledText(alerts_frame, height=12)
        self.network_alerts_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Initial network info
        self.get_network_info()
        
    def setup_firewall_tab(self):
        """Setup firewall management tab"""
        firewall_widget = ttk.Frame(self.notebook)
        self.notebook.add(firewall_widget, text="Firewall")
        
        # Block IP section
        ip_frame = ttk.LabelFrame(firewall_widget, text="Block IP Address")
        ip_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(ip_frame, text="IP Address:").pack(side='left', padx=5)
        self.ip_entry = ttk.Entry(ip_frame, width=15)
        self.ip_entry.pack(side='left', padx=5)
        self.ip_entry.insert(0, "192.168.1.100")
        
        ttk.Button(ip_frame, text="Block IP", command=self.block_ip).pack(side='left', padx=5)
        ttk.Button(ip_frame, text="Unblock IP", command=self.unblock_ip).pack(side='left', padx=5)
        
        # Block Port section  
        port_frame = ttk.LabelFrame(firewall_widget, text="Block Port")
        port_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(port_frame, text="Port Number:").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(port_frame, width=10)
        self.port_entry.pack(side='left', padx=5)
        self.port_entry.insert(0, "4444")
        
        ttk.Button(port_frame, text="Block Port", command=self.block_port).pack(side='left', padx=5)
        ttk.Button(port_frame, text="Unblock Port", command=self.unblock_port).pack(side='left', padx=5)
        
        # Blocked items display
        blocked_frame = ttk.LabelFrame(firewall_widget, text="Currently Blocked")
        blocked_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.blocked_items_text = scrolledtext.ScrolledText(blocked_frame, height=8)
        self.blocked_items_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.refresh_firewall_display()
        
    def setup_web_protection_tab(self):
        """Setup web protection tab"""
        web_widget = ttk.Frame(self.notebook)
        self.notebook.add(web_widget, text="Web Protection")
        
        # URL checking
        url_frame = ttk.LabelFrame(web_widget, text="Check URL Safety")
        url_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(url_frame, text="URL:").pack(side='left', padx=5)
        self.url_entry = ttk.Entry(url_frame, width=40)
        self.url_entry.pack(side='left', padx=5)
        self.url_entry.insert(0, "https://example.com")
        
        ttk.Button(url_frame, text="Check URL", command=self.check_url_safety).pack(side='left', padx=5)
        ttk.Button(url_frame, text="Check History", command=self.show_url_history).pack(side='left', padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(web_widget, text="URL Analysis Results")
        results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.url_results_text = scrolledtext.ScrolledText(results_frame, height=12)
        self.url_results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def setup_vulnerability_tab(self):
        """Setup vulnerability scanner tab"""
        vuln_widget = ttk.Frame(self.notebook)
        self.notebook.add(vuln_widget, text="Vulnerability Scan")
        
        # Scan controls
        control_frame = ttk.Frame(vuln_widget)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(control_frame, text="Scan System", 
                  command=self.scan_vulnerabilities).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Generate Report", 
                  command=self.generate_vuln_report).pack(side='left', padx=5)
        
        # Summary frame
        summary_frame = ttk.LabelFrame(vuln_widget, text="Scan Summary")
        summary_frame.pack(fill='x', padx=5, pady=5)
        
        self.vuln_summary_text = scrolledtext.ScrolledText(summary_frame, height=3)
        self.vuln_summary_text.pack(fill='x', padx=5, pady=5)
        
        # Results display
        results_frame = ttk.LabelFrame(vuln_widget, text="Vulnerability Scan Results")
        results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.vuln_results_text = scrolledtext.ScrolledText(results_frame, height=10)
        self.vuln_results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def setup_quarantine_tab(self):
        """Setup quarantine management tab"""
        self.quarantine_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.quarantine_frame, text="Quarantine")
        
        # Controls
        control_frame = ttk.Frame(self.quarantine_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_quarantine).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Restore Selected", command=self.restore_selected).pack(side='left', padx=5)
        
        # Quarantine list
        list_frame = ttk.LabelFrame(self.quarantine_frame, text="Quarantined Files")
        list_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.quarantine_listbox = tk.Listbox(list_frame)
        self.quarantine_listbox.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.refresh_quarantine()

    def setup_background_updates(self):
        """Setup background updates for real-time features"""
        def update_dashboard():
            if hasattr(self, 'dashboard_alerts'):
                # Get alerts from all monitoring systems
                alerts = self.file_monitor.get_alerts()
                if alerts:
                    for alert in alerts:
                        self.dashboard_alerts.insert(tk.END, f"{alert}\n")
                        self.dashboard_alerts.see(tk.END)
            
            self.root.after(5000, update_dashboard)  # Update every 5 seconds
        
        update_dashboard()

    # FILE SCANNER METHODS
    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select file to scan")
        if filename:
            self.file_path_var.set(filename)
            
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self.file_path_var.set(folder)
            
    def start_scan(self):
        target = self.file_path_var.get()
        if not target or not os.path.exists(target):
            messagebox.showerror("Error", "Please select a valid file or folder")
            return
            
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Scanning...")
        self.progress['value'] = 0
        
        def scan_thread():
            try:
                for i in range(0, 101, 20):
                    self.progress['value'] = i
                    time.sleep(0.1)
                
                if os.path.isfile(target):
                    results = [self.scanner.scan_file(target)]
                else:
                    results = self.scanner.scan_directory(target)
                
                self.root.after(0, lambda: self.display_results(results))
                self.root.after(0, lambda: self.progress.config(value=100))
                self.root.after(0, lambda: self.status_var.set("Scan completed"))
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
            
    def display_results(self, results):
        infected_count = 0
        for result in results:
            status_icon = "✅" if result["status"] == "CLEAN" else "❌"
            self.results_text.insert(tk.END, f"{status_icon} {result['file']} - {result['status']}\n")
            if result["status"] == "INFECTED":
                infected_count += 1
                
        summary = self.scanner.get_scan_summary()
        self.results_text.insert(tk.END, f"\n📊 Scan Summary:\n")
        self.results_text.insert(tk.END, f"Total files: {summary['total_files']}\n")
        self.results_text.insert(tk.END, f"Infected: {summary['infected_files']}\n")
        
        if infected_count > 0:
            messagebox.showwarning("Threats Found", f"Found {infected_count} infected files!")

    # REAL-TIME MONITORING METHODS
    def toggle_realtime_monitoring(self):
        if not self.realtime_monitoring:
            if self.file_monitor.start_monitoring():
                self.realtime_monitoring = True
                self.realtime_btn.config(text="Stop Real-Time Monitoring")
                self.realtime_alerts.insert(tk.END, "✅ Real-time monitoring started\n")
                self.status_var.set("Real-time monitoring active")
        else:
            if self.file_monitor.stop_monitoring():
                self.realtime_monitoring = False
                self.realtime_btn.config(text="Start Real-Time Monitoring")
                self.realtime_alerts.insert(tk.END, "🛑 Real-time monitoring stopped\n")
                self.status_var.set("Real-time monitoring stopped")

    # NETWORK MONITOR METHODS
    def get_network_info(self):
        def _get_info():
            try:
                info = self.network_monitor.get_network_info()
                self.root.after(0, lambda: self._display_network_info(info))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to get network info: {e}"))
        threading.Thread(target=_get_info, daemon=True).start()

    def _display_network_info(self, info):
        self.network_info_text.delete(1.0, tk.END)
        self.network_info_text.insert(tk.END, f"Hostname: {info['hostname']}\n")
        self.network_info_text.insert(tk.END, f"Local IP: {info['local_ip']}\n")
        self.network_info_text.insert(tk.END, f"Timestamp: {time.ctime(info['timestamp'])}\n")

    def scan_connections(self):
        def _scan_conn():
            try:
                self.root.after(0, lambda: self.network_alerts_text.insert(tk.END, "🔍 Scanning connections...\n"))
                connections = self.network_monitor.get_network_connections()
                alerts = self.network_monitor.analyze_connections(connections)
                
                self.root.after(0, lambda: self._display_connections(connections, alerts))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Connection scan failed: {e}"))
        threading.Thread(target=_scan_conn, daemon=True).start()

    def _display_connections(self, connections, alerts):
        self.network_alerts_text.insert(tk.END, f"📡 Found {len(connections)} connections\n")
        for alert in alerts:
            self.network_alerts_text.insert(tk.END, f"⚠️ {alert['type']}: {alert['local_address']}\n")
        if not alerts:
            self.network_alerts_text.insert(tk.END, "✅ No suspicious connections\n")
        self.network_alerts_text.see(tk.END)

    def port_scan(self):
        def _port_scan():
            try:
                self.root.after(0, lambda: self.network_alerts_text.insert(tk.END, "🔍 Port scanning...\n"))
                results = []
                ports = [80, 443, 22, 21, 3389]
                
                for port in ports:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(1)
                            result = sock.connect_ex(("127.0.0.1", port))
                            status = 'OPEN' if result == 0 else 'CLOSED'
                            results.append((port, status))
                    except:
                        results.append((port, 'ERROR'))
                
                self.root.after(0, lambda: self._display_port_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Port scan failed: {e}"))
        threading.Thread(target=_port_scan, daemon=True).start()

    def _display_port_results(self, results):
        for port, status in results:
            icon = "✅" if status == 'OPEN' else "❌"
            self.network_alerts_text.insert(tk.END, f"{icon} Port {port}: {status}\n")
        self.network_alerts_text.see(tk.END)

    def toggle_network_monitoring(self):
        if not self.network_monitoring:
            self.start_network_monitoring()
        else:
            self.stop_network_monitoring()

    def start_network_monitoring(self):
        self.network_monitoring = True
        self.monitor_btn.config(text="Stop Monitoring")
        self.network_alerts_text.insert(tk.END, "🛡️ Network monitoring started\n")

    def stop_network_monitoring(self):
        self.network_monitoring = False
        self.monitor_btn.config(text="Start Monitoring")
        self.network_alerts_text.insert(tk.END, "🛑 Network monitoring stopped\n")

    # FIREWALL METHODS
    def block_ip(self):
        ip = self.ip_entry.get().strip()
        if self.firewall.block_ip(ip):
            messagebox.showinfo("Success", f"IP {ip} blocked successfully")
            self.refresh_firewall_display()
        else:
            messagebox.showerror("Error", "Invalid IP address or already blocked")

    def unblock_ip(self):
        ip = self.ip_entry.get().strip()
        if self.firewall.unblock_ip(ip):
            messagebox.showinfo("Success", f"IP {ip} unblocked")
            self.refresh_firewall_display()
        else:
            messagebox.showerror("Error", "IP not found in block list")

    def block_port(self):
        try:
            port = int(self.port_entry.get())
            if self.firewall.block_port(port):
                messagebox.showinfo("Success", f"Port {port} blocked successfully")
                self.refresh_firewall_display()
            else:
                messagebox.showerror("Error", "Invalid port or already blocked")
        except:
            messagebox.showerror("Error", "Please enter a valid port number")

    def unblock_port(self):
        try:
            port = int(self.port_entry.get())
            if self.firewall.unblock_port(port):
                messagebox.showinfo("Success", f"Port {port} unblocked")
                self.refresh_firewall_display()
            else:
                messagebox.showerror("Error", "Port not found in block list")
        except:
            messagebox.showerror("Error", "Please enter a valid port number")

    def refresh_firewall_display(self):
        blocked = self.firewall.get_blocked_items()
        self.blocked_items_text.delete(1.0, tk.END)
        self.blocked_items_text.insert(tk.END, "Blocked IPs:\n")
        for ip in blocked['blocked_ips']:
            self.blocked_items_text.insert(tk.END, f"  • {ip}\n")
        self.blocked_items_text.insert(tk.END, "\nBlocked Ports:\n")
        for port in blocked['blocked_ports']:
            self.blocked_items_text.insert(tk.END, f"  • {port}\n")

    # WEB PROTECTION METHODS
    def check_url_safety(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        result = self.web_shield.check_url(url)
        
        self.url_results_text.delete(1.0, tk.END)
        self.url_results_text.insert(tk.END, f"URL: {result['url']}\n")
        self.url_results_text.insert(tk.END, f"Safe: {'✅ Yes' if result['safe'] else '❌ No'}\n")
        self.url_results_text.insert(tk.END, f"Risk Level: {result['risk_level']}\n")
        self.url_results_text.insert(tk.END, f"Confidence: {result['confidence']}%\n\n")
        
        if result['threats']:
            self.url_results_text.insert(tk.END, "Threats Detected:\n")
            for threat in result['threats']:
                self.url_results_text.insert(tk.END, f"• {threat}\n")
        else:
            self.url_results_text.insert(tk.END, "✅ No threats detected\n")

    def show_url_history(self):
        history = self.web_shield.get_check_history()
        self.url_results_text.delete(1.0, tk.END)
        self.url_results_text.insert(tk.END, "Recent URL Checks:\n")
        self.url_results_text.insert(tk.END, "=" * 50 + "\n")
        for check in history:
            status = "✅ SAFE" if check['safe'] else "❌ UNSAFE"
            self.url_results_text.insert(tk.END, f"{status} - {check['url']}\n")

    # VULNERABILITY SCANNER METHODS
    def scan_vulnerabilities(self):
        def _scan():
            try:
                vulnerabilities = self.vulnerability_scanner.scan_system()
                summary = self.vulnerability_scanner.get_scan_summary()
                
                self.root.after(0, lambda: self._display_vulnerabilities(vulnerabilities, summary))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Vulnerability scan failed: {e}"))
        
        threading.Thread(target=_scan, daemon=True).start()

    def _display_vulnerabilities(self, vulnerabilities, summary):
        self.vuln_summary_text.delete(1.0, tk.END)
        self.vuln_summary_text.insert(tk.END, 
            f"Vulnerabilities Found: {summary['total_vulnerabilities']} | "
            f"High Severity: {summary['high_severity']} | "
            f"Last Scan: {summary['last_scan']}\n")
        
        self.vuln_results_text.delete(1.0, tk.END)
        if not vulnerabilities:
            self.vuln_results_text.insert(tk.END, "✅ No vulnerabilities found!\n")
            return
            
        for vuln in vulnerabilities:
            severity_icon = "🔴" if vuln['severity'] == 'HIGH' else "🟡" if vuln['severity'] == 'MEDIUM' else "🟢"
            self.vuln_results_text.insert(tk.END, 
                f"{severity_icon} {vuln['type']} ({vuln['severity']})\n")
            self.vuln_results_text.insert(tk.END, f"   Description: {vuln['description']}\n")
            self.vuln_results_text.insert(tk.END, f"   Fix: {vuln['fix']}\n")
            self.vuln_results_text.insert(tk.END, f"   Category: {vuln['category']}\n\n")

    def generate_vuln_report(self):
        summary = self.vulnerability_scanner.get_scan_summary()
        messagebox.showinfo("Report Generated", 
                          f"Vulnerability Report:\n"
                          f"Total Issues: {summary['total_vulnerabilities']}\n"
                          f"High Severity: {summary['high_severity']}\n"
                          f"Last Scan: {summary['last_scan']}")

    # QUARANTINE METHODS
    def refresh_quarantine(self):
        self.quarantine_listbox.delete(0, tk.END)
        files = self.quarantine_manager.get_quarantined_files()
        for file in files:
            self.quarantine_listbox.insert(tk.END, file)
            
    def restore_selected(self):
        selected = self.quarantine_listbox.curselection()
        if not selected:
            messagebox.showinfo("Info", "Please select a file to restore")
            return
        filename = self.quarantine_listbox.get(selected[0])
        messagebox.showinfo("Restore", f"Would restore {filename}")

    # QUICK ACTION METHODS
    def quick_scan(self):
        self.file_path_var.set("samples")
        self.start_scan()

    def quick_vulnerability_scan(self):
        self.notebook.select(6)  # Switch to vulnerability tab
        self.scan_vulnerabilities()

    def quick_network_scan(self):
        self.notebook.select(3)  # Switch to network tab
        self.port_scan()

    def clear_network_log(self):
        self.network_alerts_text.delete(1.0, tk.END)

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.progress['value'] = 0

def main():
    root = tk.Tk()
    app = CompleteAntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()