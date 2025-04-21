
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import random
import os
from PIL import Image, ImageTk

class DefendSysApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DefendSys Antivirus")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.root.configure(bg="#f0f2f5")
        
        # Set app icon if available
        try:
            self.root.iconbitmap("shield.ico")
        except:
            pass
            
        # Colors
        self.primary_color = "#1e88e5"  # Blue
        self.secondary_color = "#e53935"  # Red for threats
        self.success_color = "#43a047"  # Green for success
        self.bg_color = "#f0f2f5"  # Light gray background
        
        # Create main frame
        self.main_frame = tk.Frame(self.root, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create sidebar
        self.create_sidebar()
        
        # Create content frame
        self.content_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Initialize scan variables
        self.scan_progress = 0
        self.scan_running = False
        self.scan_type = ""
        self.threats_found = []
        
        # Show dashboard by default
        self.show_dashboard()
    
    def create_sidebar(self):
        sidebar = tk.Frame(self.main_frame, width=200, bg="#ffffff", relief=tk.RIDGE, borderwidth=1)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar.pack_propagate(False)  # Prevent the sidebar from shrinking
        
        # Logo
        logo_frame = tk.Frame(sidebar, bg="#ffffff")
        logo_frame.pack(fill=tk.X, padx=10, pady=20)
        
        logo_label = tk.Label(logo_frame, text="DefendSys", font=("Arial", 20, "bold"), fg=self.primary_color, bg="#ffffff")
        logo_label.pack()
        
        # Navigation buttons
        nav_buttons = [
            ("Dashboard", self.show_dashboard),
            ("Scan", self.show_scan_page),
            ("Threats", self.show_threats_page),
            ("Settings", self.show_settings_page)
        ]
        
        for text, command in nav_buttons:
            btn = tk.Button(
                sidebar,
                text=text,
                font=("Arial", 12),
                bg="#ffffff",
                fg="#333333",
                bd=0,
                activebackground="#e6f2ff",
                activeforeground=self.primary_color,
                padx=10,
                pady=8,
                width=15,
                anchor=tk.W,
                command=command,
                cursor="hand2"
            )
            btn.pack(fill=tk.X, padx=5, pady=2)
    
    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def show_dashboard(self):
        self.clear_content()
        
        # Dashboard header
        header = tk.Label(self.content_frame, text="Dashboard", font=("Arial", 18, "bold"), bg=self.bg_color)
        header.pack(anchor=tk.W, pady=(0, 20))
        
        # Status cards container
        cards_frame = tk.Frame(self.content_frame, bg=self.bg_color)
        cards_frame.pack(fill=tk.X, pady=10)
        
        # Protection status card
        protection_card = tk.Frame(cards_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        protection_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        tk.Label(protection_card, text="Protection Status", font=("Arial", 14, "bold"), bg="#ffffff").pack(anchor=tk.W, padx=15, pady=10)
        
        status_frame = tk.Frame(protection_card, bg="#ffffff")
        status_frame.pack(fill=tk.X, padx=15, pady=5)
        
        tk.Label(status_frame, text="Status:", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT)
        tk.Label(status_frame, text="Protected", font=("Arial", 12, "bold"), fg=self.success_color, bg="#ffffff").pack(side=tk.LEFT, padx=5)
        
        # Last scan frame
        last_scan_frame = tk.Frame(protection_card, bg="#ffffff")
        last_scan_frame.pack(fill=tk.X, padx=15, pady=5)
        
        tk.Label(last_scan_frame, text="Last Scan:", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT)
        tk.Label(last_scan_frame, text="Today, 10:30 AM", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT, padx=5)
        
        # System summary card
        summary_card = tk.Frame(cards_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        summary_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(summary_card, text="System Summary", font=("Arial", 14, "bold"), bg="#ffffff").pack(anchor=tk.W, padx=15, pady=10)
        
        # CPU usage
        cpu_frame = tk.Frame(summary_card, bg="#ffffff")
        cpu_frame.pack(fill=tk.X, padx=15, pady=5)
        
        tk.Label(cpu_frame, text="CPU Usage:", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT)
        tk.Label(cpu_frame, text="32%", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT, padx=5)
        
        # Memory usage
        memory_frame = tk.Frame(summary_card, bg="#ffffff")
        memory_frame.pack(fill=tk.X, padx=15, pady=5)
        
        tk.Label(memory_frame, text="Memory Usage:", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT)
        tk.Label(memory_frame, text="2.1GB / 8GB", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT, padx=5)
        
        # Real-time protection card
        rt_protection_frame = tk.Frame(self.content_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        rt_protection_frame.pack(fill=tk.X, pady=15)
        
        tk.Label(rt_protection_frame, text="Real-time Protection", font=("Arial", 14, "bold"), bg="#ffffff").pack(anchor=tk.W, padx=15, pady=10)
        
        # Features list
        features = ["File Shield", "Web Shield", "Mail Shield", "Behavior Shield"]
        status = ["Active", "Active", "Active", "Active"]
        
        for i, (feature, status_text) in enumerate(zip(features, status)):
            feature_frame = tk.Frame(rt_protection_frame, bg="#ffffff")
            feature_frame.pack(fill=tk.X, padx=15, pady=5)
            
            tk.Label(feature_frame, text=f"{feature}:", font=("Arial", 12), bg="#ffffff").pack(side=tk.LEFT)
            status_color = self.success_color if status_text == "Active" else self.secondary_color
            tk.Label(feature_frame, text=status_text, font=("Arial", 12, "bold"), fg=status_color, bg="#ffffff").pack(side=tk.LEFT, padx=5)
    
    def show_scan_page(self):
        self.clear_content()
        
        # Scan header
        header = tk.Label(self.content_frame, text="Scan Center", font=("Arial", 18, "bold"), bg=self.bg_color)
        header.pack(anchor=tk.W, pady=(0, 20))
        
        # Scan options frame
        scan_options_frame = tk.Frame(self.content_frame, bg=self.bg_color)
        scan_options_frame.pack(fill=tk.X, pady=10)
        
        # Quick scan
        quick_scan_card = tk.Frame(scan_options_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        quick_scan_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10), pady=10)
        
        tk.Label(quick_scan_card, text="Quick Scan", font=("Arial", 14, "bold"), bg="#ffffff").pack(anchor=tk.CENTER, padx=15, pady=10)
        tk.Label(quick_scan_card, text="Scan most common areas\nwhere threats hide", font=("Arial", 10), bg="#ffffff", justify=tk.CENTER).pack(pady=5)
        
        ttk.Button(quick_scan_card, text="Start Quick Scan", command=lambda: self.start_scan("quick")).pack(pady=15)
        
        # Deep scan
        deep_scan_card = tk.Frame(scan_options_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        deep_scan_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10), pady=10)
        
        tk.Label(deep_scan_card, text="Deep Scan", font=("Arial", 14, "bold"), bg="#ffffff").pack(anchor=tk.CENTER, padx=15, pady=10)
        tk.Label(deep_scan_card, text="Complete system scan\nincluding all files and programs", font=("Arial", 10), bg="#ffffff", justify=tk.CENTER).pack(pady=5)
        
        ttk.Button(deep_scan_card, text="Start Deep Scan", command=lambda: self.start_scan("deep")).pack(pady=15)
        
        # Custom scan
        custom_scan_card = tk.Frame(scan_options_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        custom_scan_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=10)
        
        tk.Label(custom_scan_card, text="Custom Scan", font=("Arial", 14, "bold"), bg="#ffffff").pack(anchor=tk.CENTER, padx=15, pady=10)
        tk.Label(custom_scan_card, text="Scan specific files\nor folders", font=("Arial", 10), bg="#ffffff", justify=tk.CENTER).pack(pady=5)
        
        ttk.Button(custom_scan_card, text="Browse Files", command=self.browse_files).pack(pady=15)
        
        # Scan progress frame (hidden by default)
        self.scan_progress_frame = tk.Frame(self.content_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        self.scan_progress_bar = ttk.Progressbar(self.scan_progress_frame, length=500, mode="determinate")
        self.scan_status_label = tk.Label(self.scan_progress_frame, text="", font=("Arial", 10), bg="#ffffff")
        self.scan_file_label = tk.Label(self.scan_progress_frame, text="", font=("Arial", 9), bg="#ffffff", fg="#666666")
        self.cancel_button = ttk.Button(self.scan_progress_frame, text="Cancel", command=self.cancel_scan)
    
    def show_threats_page(self):
        self.clear_content()
        
        # Threats header
        header = tk.Label(self.content_frame, text="Threats", font=("Arial", 18, "bold"), bg=self.bg_color)
        header.pack(anchor=tk.W, pady=(0, 20))
        
        # Create threats treeview
        columns = ("id", "name", "type", "location", "status")
        tree = ttk.Treeview(self.content_frame, columns=columns, show="headings")
        
        # Define headings
        tree.heading("id", text="#")
        tree.heading("name", text="Threat Name")
        tree.heading("type", text="Type")
        tree.heading("location", text="Location")
        tree.heading("status", text="Status")
        
        # Define columns
        tree.column("id", width=50)
        tree.column("name", width=150)
        tree.column("type", width=100)
        tree.column("location", width=200)
        tree.column("status", width=100)
        
        # Add some sample threats
        sample_threats = [
            (1, "Trojan.Win32.Generic", "Trojan", "C:\\Windows\\Temp\\suspicious.exe", "Quarantined"),
            (2, "Adware.Win32.Amonetize", "Adware", "C:\\Program Files\\Adware\\Program.exe", "Deleted"),
            (3, "PUP.Optional.WebToolbar", "PUP", "C:\\Users\\AppData\\Roaming\\WebToolbar", "Quarantined"),
        ]
        
        for item in sample_threats:
            tree.insert("", tk.END, values=item)
            
        tree.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Add actions buttons
        buttons_frame = tk.Frame(self.content_frame, bg=self.bg_color)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="Remove Selected", command=self.remove_threat).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Quarantine Selected", command=self.quarantine_threat).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Restore Selected", command=self.restore_threat).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Scan Again", command=lambda: self.start_scan("quick")).pack(side=tk.LEFT, padx=5)
    
    def show_settings_page(self):
        self.clear_content()
        
        # Settings header
        header = tk.Label(self.content_frame, text="Settings", font=("Arial", 18, "bold"), bg=self.bg_color)
        header.pack(anchor=tk.W, pady=(0, 20))
        
        # Settings frame
        settings_frame = tk.Frame(self.content_frame, bg="#ffffff", relief=tk.GROOVE, bd=1)
        settings_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Scan settings section
        scan_header = tk.Label(settings_frame, text="Scan Settings", font=("Arial", 14, "bold"), bg="#ffffff")
        scan_header.pack(anchor=tk.W, padx=20, pady=(20, 10))
        
        # Checkbox options
        scan_vars = {}
        scan_options = [
            "Scan compressed archives",
            "Scan system folders",
            "Scan for PUPs (Potentially Unwanted Programs)",
            "Enable heuristic analysis"
        ]
        
        for option in scan_options:
            var = tk.BooleanVar(value=True)
            scan_vars[option] = var
            check = ttk.Checkbutton(settings_frame, text=option, variable=var)
            check.pack(anchor=tk.W, padx=25, pady=3)
        
        # Protection settings section
        protection_header = tk.Label(settings_frame, text="Protection Settings", font=("Arial", 14, "bold"), bg="#ffffff")
        protection_header.pack(anchor=tk.W, padx=20, pady=(20, 10))
        
        # Protection options
        protection_vars = {}
        protection_options = [
            "Enable real-time file protection",
            "Enable web protection",
            "Enable email protection",
            "Start DefendSys at system startup"
        ]
        
        for option in protection_options:
            var = tk.BooleanVar(value=True)
            protection_vars[option] = var
            check = ttk.Checkbutton(settings_frame, text=option, variable=var)
            check.pack(anchor=tk.W, padx=25, pady=3)
        
        # Save button
        save_button = ttk.Button(settings_frame, text="Save Settings", command=self.save_settings)
        save_button.pack(anchor=tk.E, padx=20, pady=20)
    
    def browse_files(self):
        filetypes = (
            ('All files', '*.*'),
            ('Text files', '*.txt'),
            ('Executable files', '*.exe')
        )
        
        filename = filedialog.askopenfilename(
            title='Select a file to scan',
            initialdir='/',
            filetypes=filetypes
        )
        
        if filename:
            self.start_file_scan(filename)
    
    def start_scan(self, scan_type):
        self.scan_type = scan_type
        self.scan_running = True
        self.scan_progress = 0
        
        # Show scan progress frame
        self.scan_progress_frame.pack(fill=tk.X, pady=20)
        self.scan_progress_bar.pack(fill=tk.X, padx=20, pady=10)
        self.scan_status_label.pack(pady=5)
        self.scan_file_label.pack(pady=5)
        self.cancel_button.pack(pady=10)
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def start_file_scan(self, file_path):
        self.scan_type = "custom"
        self.scan_running = True
        self.scan_progress = 0
        
        # Show scan progress frame
        self.scan_progress_frame.pack(fill=tk.X, pady=20)
        self.scan_progress_bar.pack(fill=tk.X, padx=20, pady=10)
        self.scan_status_label.pack(pady=5)
        self.scan_file_label.pack(pady=5)
        self.cancel_button.pack(pady=10)
        
        # Set file name
        self.scan_status_label.config(text=f"Scanning file: {os.path.basename(file_path)}")
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=lambda: self.run_file_scan(file_path))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self):
        """Simulates a scan process with random progress updates"""
        self.threats_found = []
        scan_duration = 100 if self.scan_type == "deep" else 50
        
        self.scan_status_label.config(text=f"{self.scan_type.capitalize()} scan in progress...")
        
        # Mock file paths to show in the scan
        file_paths = [
            # "C:\\Windows\\System32\\drivers\\etc\\hosts",
            # "C:\\Program Files\\Example\\app.exe",
            # "C:\\Users\\User\\Documents\\file.txt",
            # "C:\\Users\\User\\Downloads\\setup.exe",
            # "C:\\Program Files (x86)\\Common Files\\example.dll"
            "C:\\Users\\aarus\\OneDrive\\Documents"
            "C:\\Users\\aarus\Downloads"
        ]
        
        for i in range(scan_duration):
            if not self.scan_running:
                # Scan was cancelled
                return
                
            # Update progress
            self.scan_progress = (i + 1) * 100 // scan_duration
            self.scan_progress_bar["value"] = self.scan_progress
            
            # Simulate finding a file
            if i % 5 == 0:
                current_file = random.choice(file_paths)
                self.scan_file_label.config(text=f"Scanning: {current_file}")
            
            # Simulate finding a threat (10% chance per iteration)
            if random.random() < 0.05:
                threat_types = ["Trojan", "Adware", "PUP", "Worm", "Spyware"]
                threat = {
                    "name": f"{random.choice(threat_types)}.Win32.Generic",
                    "type": random.choice(threat_types),
                    "location": random.choice(file_paths)
                }
                self.threats_found.append(threat)
                
            # Update the UI
            time.sleep(0.1)
        
        # Scan completed
        self.scan_status_label.config(text=f"{self.scan_type.capitalize()} scan completed!")
        self.scan_file_label.config(text=f"Threats found: {len(self.threats_found)}")
        
        # Show scan results after completion
        self.show_scan_results()
    
    def run_file_scan(self, file_path):
        """Simulates scanning a specific file"""
        self.threats_found = []
        
        self.scan_status_label.config(text=f"Scanning file: {os.path.basename(file_path)}")
        self.scan_file_label.config(text=f"Location: {file_path}")
        
        # Simulate scanning
        for i in range(20):
            if not self.scan_running:
                # Scan was cancelled
                return
                
            # Update progress
            self.scan_progress = (i + 1) * 100 // 20
            self.scan_progress_bar["value"] = self.scan_progress
            
            # Update the UI
            time.sleep(0.1)
        
        # Randomly decide if the file is infected (30% chance)
        is_infected = random.random() < 0.3
        
        if is_infected:
            threat_types = ["Trojan", "Adware", "PUP", "Worm", "Spyware"]
            threat = {
                "name": f"{random.choice(threat_types)}.Win32.Generic",
                "type": random.choice(threat_types),
                "location": file_path
            }
            self.threats_found.append(threat)
        
        # Scan completed
        self.scan_status_label.config(text=f"File scan completed!")
        self.scan_file_label.config(text=f"Threats found: {len(self.threats_found)}")
        
        # Show scan results after completion
        self.show_scan_results()
    
    def cancel_scan(self):
        """Cancels a running scan"""
        if self.scan_running:
            self.scan_running = False
            self.scan_progress_frame.pack_forget()
            messagebox.showinfo("Scan Cancelled", "Scan has been cancelled.")
    
    def show_scan_results(self):
        """Shows the results of a scan"""
        self.scan_running = False
        
        # Hide progress components
        self.scan_progress_frame.pack_forget()
        
        # Show results dialog
        if len(self.threats_found) > 0:
            result = messagebox.askyesno(
                "Scan Results", 
                f"{len(self.threats_found)} threats found. Do you want to view them?"
            )
            if result:
                self.show_threats_page()
        else:
            messagebox.showinfo("Scan Results", "No threats found. Your system is clean!")
    
    def remove_threat(self):
        messagebox.showinfo("Remove Threat", "Selected threat(s) have been removed.")
    
    def quarantine_threat(self):
        messagebox.showinfo("Quarantine Threat", "Selected threat(s) have been quarantined.")
    
    def restore_threat(self):
        messagebox.showinfo("Restore Threat", "Selected threat(s) have been restored.")
    
    def save_settings(self):
        messagebox.showinfo("Settings", "Settings have been saved successfully!")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = DefendSysApp(root)
    root.mainloop()
