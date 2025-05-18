import customtkinter as ctk
from tkinter import messagebox, filedialog
import asyncio
import threading
import time
import queue
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from port_scanner import run_scan, cidr_to_ips
from analyzer import analyze_results
from config import DEFAULT_TIMEOUT, DEFAULT_WINDOW_SIZE, TEXTBOX_WIDTH, PREDEFINED_PORTS, LANGUAGES, NVD_API_KEY, save_nvd_api_key



class PortScannerGUI:
    def __init__(self, language="en"):
        self.root = ctk.CTk()
        self.language = language
        self.texts = LANGUAGES[language]
        self.root.title(self.texts["title"])
        self.root.geometry(DEFAULT_WINDOW_SIZE)
        self.scan_results = []
        self.progress_queue = queue.Queue()
        self.scan_running = False
        self.cancel_event = None
        self._setup_gui()
    
    def _create_input_frame(self):
        """Create the input frame with all input fields."""
        frame = ctk.CTkFrame(self.root)
        frame.pack(pady=10, padx=10, fill="x")
        
        # Target input
        ctk.CTkLabel(frame, text=self.texts["target_label"]).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_target = ctk.CTkEntry(frame, width=300)
        self.entry_target.grid(row=0, column=1, padx=5, pady=5)
        
        # Protocol selection
        ctk.CTkLabel(frame, text=self.texts["protocol_label"]).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.protocol_var = ctk.StringVar(value="Both")
        ctk.CTkOptionMenu(frame, values=["TCP", "UDP", "Both"], variable=self.protocol_var).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Scan type selection
        ctk.CTkLabel(frame, text=self.texts["scan_type_label"]).grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.scan_type_var = ctk.StringVar(value="Full Connect")
        ctk.CTkOptionMenu(frame, values=["Full Connect", "SYN Scan"], variable=self.scan_type_var).grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        # Predefined ports
        ctk.CTkLabel(frame, text=self.texts["predefined_ports_label"]).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.predefined_ports_var = ctk.StringVar(value="Custom")
        self.predefined_ports_menu = ctk.CTkOptionMenu(frame, values=list(PREDEFINED_PORTS.keys()), variable=self.predefined_ports_var, command=self.update_port_fields)
        self.predefined_ports_menu.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        
        # Start port input
        ctk.CTkLabel(frame, text=self.texts["start_port_label"]).grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.entry_start = ctk.CTkEntry(frame, width=100)
        self.entry_start.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        
        # End port input
        ctk.CTkLabel(frame, text=self.texts["end_port_label"]).grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.entry_end = ctk.CTkEntry(frame, width=100)
        self.entry_end.grid(row=5, column=1, padx=5, pady=5, sticky="w")
        
        # Timeout input
        ctk.CTkLabel(frame, text=self.texts["timeout_label"]).grid(row=6, column=0, padx=5, pady=5, sticky="w")
        self.entry_timeout = ctk.CTkEntry(frame, width=100)
        self.entry_timeout.insert(0, str(DEFAULT_TIMEOUT))
        self.entry_timeout.grid(row=6, column=1, padx=5, pady=5, sticky="w")
        
        # NVD API Key input
        ctk.CTkLabel(frame, text=self.texts["nvd_api_key_label"]).grid(row=7, column=0, padx=5, pady=5, sticky="w")
        self.entry_api_key = ctk.CTkEntry(frame, width=300, show="*")
        self.entry_api_key.insert(0, NVD_API_KEY)
        self.entry_api_key.grid(row=7, column=1, padx=5, pady=5)
        
        # Save API Key button
        ctk.CTkButton(frame, text=self.texts["save_api_key"], command=self.save_api_key).grid(row=8, column=1, padx=5, pady=5, sticky="w")
        
        return frame
    
    def _create_button_frame(self):
        """Create the button frame with all buttons."""
        frame = ctk.CTkFrame(self.root)
        frame.pack(pady=10, fill="x")
        
        ctk.CTkButton(frame, text=self.texts["start_scan"], command=self.start_scan_thread).grid(row=0, column=0, padx=10, pady=5)
        ctk.CTkButton(frame, text=self.texts["save_report"], command=self.save_results).grid(row=0, column=1, padx=10, pady=5)
        ctk.CTkButton(frame, text=self.texts["new_scan"], command=self.reset_scan).grid(row=0, column=2, padx=10, pady=5)
        ctk.CTkButton(frame, text=self.texts["cancel_scan"], command=self.cancel_scan).grid(row=0, column=3, padx=10, pady=5)
        ctk.CTkButton(frame, text=self.texts["deselect_protocol"], command=self.deselect_protocol).grid(row=0, column=4, pady=5)
        ctk.CTkButton(frame, text=self.texts["switch_language"], command=self.switch_language).grid(row=0, column=5, padx=10, pady=5)
        
        return frame
    
    def _create_result_section(self):
        """Create the result and analysis textboxes and progress bar."""
        self.result_box = ctk.CTkTextbox(self.root, width=TEXTBOX_WIDTH, height=200)
        self.result_box.pack(pady=10, padx=10)
        
        self.analysis_box = ctk.CTkTextbox(self.root, width=TEXTBOX_WIDTH, height=100)
        self.analysis_box.pack(pady=5, padx=10)
        
        self.progress_bar = ctk.CTkProgressBar(self.root, width=TEXTBOX_WIDTH)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5, padx=10)
    
    def _setup_gui(self):
        """Setup the entire GUI."""
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        if self.language == "ar":
            self.root.configure(justify="right")
            self.root.option_add("*TEntry*justify", "right")
            self.root.option_add("*TLabel*justify", "right")
        self._create_input_frame()
        self._create_button_frame()
        self._create_result_section()
    
    def save_api_key(self):
        """Save the NVD API key to settings.json."""
        api_key = self.entry_api_key.get()
        try:
            save_nvd_api_key(api_key)
            messagebox.showinfo("Success", self.texts["api_key_saved"])
        except Exception as e:
            messagebox.showerror("Error", self.texts["error"].format(error=str(e)))
    
    def update_port_fields(self, selection):
        """Update port fields based on predefined port selection."""
        self.entry_start.delete(0, ctk.END)
        self.entry_end.delete(0, ctk.END)
        if selection != "Custom" and PREDEFINED_PORTS[selection]:
            start, end = PREDEFINED_PORTS[selection][0]
            self.entry_start.insert(0, str(start))
            self.entry_end.insert(0, str(end))
            self.entry_start.configure(state="disabled")
            self.entry_end.configure(state="disabled")
        else:
            self.entry_start.configure(state="normal")
            self.entry_end.configure(state="normal")
    
    def switch_language(self):
        """Switch the GUI language and reload."""
        new_language = "ar" if self.language == "en" else "en"
        self.root.destroy()
        new_app = PortScannerGUI(language=new_language)
        new_app.run()
    
    def update_progress_bar(self):
        """Update the progress bar in a separate thread."""
        while self.scan_running:
            try:
                progress = self.progress_queue.get_nowait()
                self.progress_bar.set(progress)
            except queue.Empty:
                time.sleep(0.1)
            self.root.update()
    
    def generate_pdf_report(self, analysis, results, file_path):
        """Generate a PDF report using reportlab."""
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph(self.texts["title"], styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Summary", styles['Heading2']))
        story.append(Paragraph(self.texts["total_hosts"].format(count=analysis['total_hosts']), styles['Normal']))
        story.append(Paragraph(self.texts["open_ports"].format(count=analysis['total_open_ports']), styles['Normal']))
        story.append(Spacer(1, 12))
        if analysis['high_risk_ports']:
            story.append(Paragraph(self.texts["high_risk_ports"], styles['Heading2']))
            for risk in analysis['high_risk_ports']:
                story.append(Paragraph(risk, styles['Normal']))
            story.append(Spacer(1, 12))
        if analysis['notes']:
            story.append(Paragraph(self.texts["vulnerabilities"], styles['Heading2']))
            for vuln in analysis['notes']:
                story.append(Paragraph(vuln, styles['Normal']))
            story.append(Spacer(1, 12))
        if analysis['recommendations']:
            story.append(Paragraph(self.texts["recommendations"], styles['Heading2']))
            for rec in analysis['recommendations']:
                story.append(Paragraph(rec, styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Detailed Results", styles['Heading2']))
        for result in results:
            if isinstance(result, str):
                story.append(Paragraph(result, styles['Normal']))
            elif isinstance(result, dict) and "port" in result:
                text = f"Port {result['port']} ({result['protocol']}): {result['state']} ({result['service']})"
                if result.get("banner"):
                    text += f" | Banner: {result['banner']}"
                if result.get("risk"):
                    text += f" | Risk: {result['risk']}"
                if result.get("vuln"):
                    text += f" | Vuln: {result['vuln']}"
                story.append(Paragraph(text, styles['Normal']))
            elif isinstance(result, dict) and "os" in result:
                story.append(Paragraph(f"OS: {result['os']}", styles['Normal']))
        doc.build(story)
    
    def save_txt_report(self, file_path):
        """Save scan results and analysis as a text file."""
        with open(file_path, "w") as file:
            for r in self.scan_results:
                if isinstance(r, str):
                    file.write(r + "\n")
                elif isinstance(r, dict) and "port" in r:
                    text = f"Port {r['port']} ({r['protocol']}): {r['state']} ({r['service']})"
                    if r.get("banner"):
                        text += f" | Banner: {r['banner']}"
                    if r.get("risk"):
                        text += f" | Risk: {r['risk']}"
                    if r.get("vuln"):
                        text += f" | Vuln: {r['vuln']}"
                    file.write(text + "\n")
                elif isinstance(r, dict) and "os" in r:
                    file.write(f"OS: {r['os']}\n")
            analysis = analyze_results(self.scan_results)
            file.write(f"\n{self.texts['security_analysis']}\n")
            file.write(self.texts["total_hosts"].format(count=analysis['total_hosts']) + "\n")
            file.write(self.texts["open_ports"].format(count=analysis['total_open_ports']) + "\n\n")
            if analysis['high_risk_ports']:
                file.write(self.texts["high_risk_ports"] + "\n")
                for risk in analysis['high_risk_ports']:
                    file.write(f"- {risk}\n")
            if analysis['notes']:
                file.write(self.texts["vulnerabilities"] + "\n")
                for vuln in analysis['notes']:
                    file.write(f"- {vuln}\n")
            if analysis['recommendations']:
                file.write(self.texts["recommendations"] + "\n")
                for rec in analysis['recommendations']:
                    file.write(f"- {rec}\n")
    
    def save_results(self):
        """Save scan results as TXT or PDF."""
        if not self.scan_results:
            messagebox.showwarning("Warning", self.texts["no_results"])
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt"), ("PDF Files", "*.pdf")],
                                                 title=self.texts["save_report"])
        if file_path:
            try:
                if file_path.endswith(".pdf"):
                    analysis = analyze_results(self.scan_results)
                    self.generate_pdf_report(analysis, self.scan_results, file_path)
                else:
                    self.save_txt_report(file_path)
                messagebox.showinfo("Saved", self.texts["saved"].format(file_path=file_path))
            except Exception as e:
                messagebox.showerror("Error", self.texts["error"].format(error=str(e)))
    
    def start_scan(self):
        """Perform the port scan."""
        if self.scan_running:
            return
        
        self.scan_running = True
        self.cancel_event = asyncio.Event()
        start_time = time.time()
        target = self.entry_target.get()
        protocol = self.protocol_var.get()
        scan_type = self.scan_type_var.get()
        try:
            start_port = int(self.entry_start.get())
            end_port = int(self.entry_end.get())
            timeout = float(self.entry_timeout.get())
            if timeout <= 0:
                raise ValueError("Timeout must be positive")

            self.result_box.delete("1.0", ctk.END)
            self.analysis_box.delete("1.0", ctk.END)
            self.progress_bar.set(0)
            self.result_box.insert("1.0", self.texts["scanning"].format(target=target, start=start_port, end=end_port, protocol=protocol, scan_type=scan_type) + "\n\n")
            
            if scan_type == "SYN Scan":
                messagebox.showwarning("Warning", self.texts["root_privileges"])

            total_tasks = (end_port - start_port + 1)
            try:
                if '/' in target:
                    total_tasks *= len(cidr_to_ips(target))
                else:
                    total_tasks *= 1
            except ValueError as e:
                raise ValueError(f"Invalid CIDR notation: {e}")
            if protocol == "Both":
                total_tasks *= 2

            threading.Thread(target=self.update_progress_bar, daemon=True).start()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                if protocol == "Both":
                    tcp_results = loop.run_until_complete(run_scan(target, start_port, end_port, "TCP", timeout, scan_type, self.progress_queue, total_tasks, self.cancel_event))
                    udp_results = loop.run_until_complete(run_scan(target, start_port, end_port, "UDP", timeout, scan_type, self.progress_queue, total_tasks, self.cancel_event))
                    self.scan_results = tcp_results + udp_results
                else:
                    self.scan_results = loop.run_until_complete(run_scan(target, start_port, end_port, protocol, timeout, scan_type, self.progress_queue, total_tasks, self.cancel_event))
            finally:
                loop.close()
            
            if self.scan_results and not any("error" in r for r in self.scan_results if isinstance(r, dict)):
                for r in self.scan_results:
                    if isinstance(r, str):
                        self.result_box.insert(ctk.END, r + "\n")
                    elif isinstance(r, dict) and "port" in r:
                        text = f"Port {r['port']} ({r['protocol']}): {r['state']} ({r['service']})"
                        if r.get("banner"):
                            text += f" | Banner: {r['banner']}"
                        if r.get("risk"):
                            text += f" | Risk: {r['risk']}"
                        if r.get("vuln"):
                            text += f" | Vuln: {r['vuln']}"
                        self.result_box.insert(ctk.END, text + "\n")
                    elif isinstance(r, dict) and "os" in r:
                        self.result_box.insert(ctk.END, f"OS: {r['os']}\n")
                
                analysis = analyze_results(self.scan_results)
                self.analysis_box.insert("1.0", self.texts["security_analysis"] + "\n\n")
                self.analysis_box.insert(ctk.END, self.texts["total_hosts"].format(count=analysis['total_hosts']) + "\n")
                self.analysis_box.insert(ctk.END, self.texts["open_ports"].format(count=analysis['total_open_ports']) + "\n\n")
                if analysis['high_risk_ports']:
                    self.analysis_box.insert(ctk.END, self.texts["high_risk_ports"] + "\n")
                    for risk in analysis['high_risk_ports']:
                        self.analysis_box.insert(ctk.END, f"- {risk}\n")
                    self.analysis_box.insert(ctk.END, "\n")
                if analysis['notes']:
                    self.analysis_box.insert(ctk.END, self.texts["vulnerabilities"] + "\n")
                    for vuln in analysis['notes']:
                        self.analysis_box.insert(ctk.END, f"- {vuln}\n")
                    self.analysis_box.insert(ctk.END, "\n")
                if analysis['recommendations']:
                    self.analysis_box.insert(ctk.END, self.texts["recommendations"] + "\n")
                    for rec in analysis['recommendations']:
                        self.analysis_box.insert(ctk.END, f"- {rec}\n")
            else:
                self.result_box.insert(ctk.END, "No open ports found or error occurred.\n")
            
            duration = time.time() - start_time
            self.result_box.insert(ctk.END, f"\nâ�±ï¸� Scan completed in {duration:.2f} seconds.\n")
            messagebox.showinfo("Success", self.texts["scan_complete"])
            
        except ValueError as e:
            messagebox.showerror("Error", self.texts["invalid_input"].format(error=str(e)))
            self.result_box.insert(ctk.END, self.texts["error"].format(error=str(e)) + "\n")
        except Exception as e:
            messagebox.showerror("Error", self.texts["error"].format(error=str(e)))
            self.result_box.insert(ctk.END, self.texts["error"].format(error=str(e)) + "\n")
        finally:
            self.scan_running = False
            self.progress_bar.set(1.0)
            self.cancel_event = None
    
    def start_scan_thread(self):
        """Run the scan in a separate thread."""
        if not self.scan_running:
            threading.Thread(target=self.start_scan, daemon=True).start()
    
    def cancel_scan(self):
        """Cancel the ongoing scan."""
        if self.scan_running and self.cancel_event:
            self.cancel_event.set()
            self.scan_running = False
            self.progress_bar.set(0)
            self.result_box.delete("1.0", ctk.END)
            self.result_box.insert("1.0", self.texts["cancel_not_implemented"] + "\n")
            self.analysis_box.delete("1.0", ctk.END)
            self.scan_results = []
            messagebox.showinfo("Cancelled", self.texts["cancel_not_implemented"])
    
    def reset_scan(self):
        """Reset the GUI for a new scan."""
        if self.scan_running:
            self.cancel_scan()
        self.entry_target.delete(0, ctk.END)
        self.entry_start.delete(0, ctk.END)
        self.entry_end.delete(0, ctk.END)
        self.entry_timeout.delete(0, ctk.END)
        self.entry_timeout.insert(0, str(DEFAULT_TIMEOUT))
        self.result_box.delete("1.0", ctk.END)
        self.analysis_box.delete("1.0", ctk.END)
        self.protocol_var.set("Both")
        self.scan_type_var.set("Full Connect")
        self.predefined_ports_var.set("Custom")
        self.entry_start.configure(state="normal")
        self.entry_end.configure(state="normal")
        self.progress_bar.set(0)
        self.scan_results = []
    
    def deselect_protocol(self):
        """Set protocol to Both."""
        self.protocol_var.set("Both")
    
    def run(self):
        """Start the GUI main loop."""
        self.root.mainloop()

if __name__ == "__main__":
    app = PortScannerGUI()
    app.run()