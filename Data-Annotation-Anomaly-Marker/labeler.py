import os
import tkinter as tk
from tkinter import messagebox, ttk
import pandas as pd

class AnomalyLabelerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NIELIT - Cyber Anomaly Data Annotator")
        self.root.geometry("550x450")
        self.root.configure(bg="#f4f6f9")
        
        # Determine paths dynamically
        self.filename = "raw_network_logs.csv"
        if not os.path.exists(self.filename):
            potential_path = os.path.join("Data-Annotation-Anomaly-Marker", self.filename)
            if os.path.exists(potential_path):
                self.filename = potential_path
            else:
                messagebox.showerror("Error", f"'{self.filename}' not found!\nRun Data_Generator.py first.")
                self.root.destroy()
                return
            
        self.df = pd.read_csv(self.filename)
        self.current_index = 0
        self.labels = []
        
        # Custom UI Styling
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TButton", font=("Arial", 11, "bold"), padding=10)
        self.style.configure("Header.TLabel", font=("Arial", 14, "bold"), background="#1e3d59", foreground="white", padding=12)
        
        self.create_widgets()
        self.load_record()

    def create_widgets(self):
        # Header Banner
        header = ttk.Label(self.root, text="Network Log Annotation Interface", style="Header.TLabel", anchor="center")
        header.pack(fill=tk.X)
        
        # Progress Counter
        self.progress_label = tk.Label(self.root, text="Record: 0 / 0", 
                                       font=("Arial", 10, "bold"), fg="#17b978", bg="#f4f6f9", pady=10)
        self.progress_label.pack()
        
        # Display Box Frame
        display_frame = tk.LabelFrame(self.root, text=" Firewall Metadata Packet ", 
                                      font=("Arial", 11, "bold"), bg="white", bd=2, relief=tk.GROOVE)
        display_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
        
        # Text Metrics Variables
        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar()
        self.proto_var = tk.StringVar()
        self.bytes_var = tk.StringVar()
        
        # Grid layout for network metrics
        labels_text = ["Source IP:", "Target Port:", "Protocol:", "Volume Sent:"]
        variables = [self.ip_var, self.port_var, self.proto_var, self.bytes_var]
        
        for idx, text in enumerate(labels_text):
            tk.Label(display_frame, text=text, font=("Arial", 10, "bold"), bg="white", fg="#555").grid(row=idx, column=0, sticky=tk.W, padx=20, pady=8)
            tk.Label(display_frame, textvariable=variables[idx], font=("Courier", 11, "bold"), bg="white", fg="#000").grid(row=idx, column=1, sticky=tk.W, padx=10, pady=8)

        # Interactive Button Layout Frame
        btn_frame = tk.Frame(self.root, bg="#f4f6f9")
        btn_frame.pack(pady=20)
        
        normal_btn = ttk.Button(btn_frame, text=" Normal (0)", command=lambda: self.assign_label(0))
        normal_btn.grid(row=0, column=0, padx=15)
        
        anomaly_btn = ttk.Button(btn_frame, text=" Anomaly (1)", command=lambda: self.assign_label(1))
        anomaly_btn.grid(row=0, column=1, padx=15)

    def load_record(self):
        if self.current_index < len(self.df):
            row = self.df.iloc[self.current_index]
            self.progress_label.config(text=f"Processing Record: {self.current_index + 1} of {len(self.df)}")
            
            # Convert all row keys to lowercase to eliminate case-sensitivity bugs entirely
            row_lower = {str(k).lower(): v for k, v in row.to_dict().items()}
            
            # Fetch variables using lowercase keys
            self.ip_var.set(row_lower.get('source_ip', 'Unknown'))
            self.port_var.set(row_lower.get('dest_port', 'Unknown'))
            self.proto_var.set(row_lower.get('protocol', 'Unknown'))
            
            # Fetch bytes safely using lowercase keys
            bytes_val = row_lower.get('bytes_sent', 0)
            try:
                self.bytes_var.set(f"{int(bytes_val):,} Bytes")
            except (ValueError, TypeError):
                self.bytes_var.set(f"{bytes_val} Bytes")
        else:
            self.finalize_dataset()

    def assign_label(self, val):
        self.labels.append(val)
        self.current_index += 1
        self.load_record()

    def finalize_dataset(self):
        # double-check alignment sizes to absolutely prevent value/index crashes
        if len(self.labels) != len(self.df):
            messagebox.showerror("Error", "Label synchronization mismatch. Restarting dataset tracking instance.")
            self.root.destroy()
            return
            
        self.df['Security_Label'] = self.labels
        
        output_file = "final_annotated_security_logs.csv"
        if "Data-Annotation-Anomaly-Marker" in self.filename:
            output_file = os.path.join("Data-Annotation-Anomaly-Marker", output_file)
            
        self.df.to_csv(output_file, index=False)
        
        distribution = self.df['Security_Label'].value_counts()
        normal_count = distribution.get(0, 0)
        anomaly_count = distribution.get(1, 0)
        
        summary_msg = f"Data Saved Successfully!\n\nNormal Logs (0): {normal_count}\nAnomalous Logs (1): {anomaly_count}"
        messagebox.showinfo("Session Finished", summary_msg)
        self.root.destroy()

if __name__ == "__main__":
    window = tk.Tk()
    app = AnomalyLabelerApp(window)
    window.mainloop()
