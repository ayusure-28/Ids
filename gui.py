import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import requests
import json
import threading
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.dates as mdates
import matplotlib.ticker as mticker
from datetime import datetime
import time
import queue
import math

FLASK_API_URL = "http://127.0.0.1:5000"

class IDPS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python IDPS Dashboard")
        self.root.geometry("900x700")

        # --- Style ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("TButton", font=("Helvetica", 10))
        style.configure("TLabelframe.Label", font=("Helvetica", 12, "bold"))
        style.configure("Live.TLabel", font=("Helvetica", 10, "bold"))
        style.configure("TNotebook.Tab", font=("Helvetica", 10, "bold"))

        # --- Create Tabbed Interface ---
        self.notebook = ttk.Notebook(root)
        
        self.dashboard_tab = ttk.Frame(self.notebook, padding="10")
        self.alerts_tab = ttk.Frame(self.notebook, padding="10")
        self.logs_tab = ttk.Frame(self.notebook, padding="10")

        self.notebook.add(self.dashboard_tab, text='Dashboard')
        self.notebook.add(self.alerts_tab, text='Alerts & Blocking')
        self.notebook.add(self.logs_tab, text='Logs & Reports')
        
        self.notebook.pack(expand=True, fill=tk.BOTH)

        self.create_dashboard_tab()
        self.create_alerts_tab()
        self.create_logs_tab()

        # --- Queue & Threading ---
        self.data_queue = queue.Queue()
        self.running = True
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.poll_thread = threading.Thread(target=self.poll_backend_data, daemon=True)
        self.poll_thread.start()
        
        self.process_gui_queue()

    # --- TAB 1: DASHBOARD ---
    def create_dashboard_tab(self):
        control_frame = ttk.LabelFrame(self.dashboard_tab, text="Monitoring Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=5)

        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_sniffer)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_sniffer, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.status_label = ttk.Label(control_frame, text="Status: Unknown", font=("Helvetica", 10, "bold"), foreground="orange")
        self.status_label.pack(side=tk.RIGHT, padx=10)

        self.alert_count_label = ttk.Label(control_frame, text="Alerts: 0", style="Live.TLabel")
        self.alert_count_label.pack(side=tk.RIGHT, padx=10)

        self.packet_count_label = ttk.Label(control_frame, text="Packets: 0", style="Live.TLabel")
        self.packet_count_label.pack(side=tk.RIGHT, padx=10)
        
        graph_frame = ttk.LabelFrame(self.dashboard_tab, text="Live Threat Monitor", padding="10")
        graph_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.fig = Figure(figsize=(5, 4), dpi=100)
        self.fig.patch.set_facecolor('#f0f0f0')
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.ax.set_title("Alerts per Minute (Last 30 Mins)")
        self.fig.tight_layout()

    # --- TAB 2: ALERTS & BLOCKING ---
    def create_alerts_tab(self):
        blocking_controls = ttk.LabelFrame(self.alerts_tab, text="Prevention Controls", padding="10")
        blocking_controls.pack(fill=tk.X, pady=5)
        
        self.manual_block_button = ttk.Button(blocking_controls, text="Block IP Manually", command=self.manual_block_ip)
        self.manual_block_button.pack(side=tk.LEFT, padx=5)
        
        self.unblock_button = ttk.Button(blocking_controls, text="Unblock Selected IP", command=self.unblock_selected_ip)
        self.unblock_button.pack(side=tk.LEFT, padx=5)
        
        self.auto_block_var = tk.BooleanVar(value=False)
        self.auto_block_toggle = ttk.Checkbutton(blocking_controls, text="Auto-Block ON/OFF", variable=self.auto_block_var, command=self.toggle_autoblock)
        self.auto_block_toggle.pack(side=tk.LEFT, padx=10)

        content_frame = ttk.Frame(self.alerts_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        alert_frame = ttk.LabelFrame(content_frame, text="Live Alerts (Last 20)", padding="10")
        alert_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 5))
        
        self.alert_tree = ttk.Treeview(alert_frame, columns=("time", "type", "src", "dst"), show="headings", height=10)
        self.alert_tree.heading("time", text="Timestamp")
        self.alert_tree.heading("type", text="Alert Type")
        self.alert_tree.heading("src", text="Source IP")
        self.alert_tree.heading("dst", text="Dest IP")
        self.alert_tree.column("time", width=140)
        self.alert_tree.column("type", width=100)
        self.alert_tree.column("src", width=120)
        self.alert_tree.column("dst", width=120)
        self.alert_tree.pack(fill=tk.BOTH, expand=True)
        
        blocked_frame = ttk.LabelFrame(content_frame, text="Blocked IPs", padding="10")
        blocked_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(5, 0))
        
        self.blocked_tree = ttk.Treeview(blocked_frame, columns=("ip", "time", "reason"), show="headings", height=10)
        self.blocked_tree.heading("ip", text="IP Address")
        self.blocked_tree.heading("time", text="Time Blocked")
        self.blocked_tree.heading("reason", text="Reason")
        self.blocked_tree.column("ip", width=120)
        self.blocked_tree.column("time", width=140)
        self.blocked_tree.column("reason", width=150)
        self.blocked_tree.pack(fill=tk.BOTH, expand=True)

    # --- TAB 3: LOGS & REPORTS ---
    def create_logs_tab(self):
        controls_frame = ttk.LabelFrame(self.logs_tab, text="Report Management", padding="10")
        controls_frame.pack(fill=tk.X, pady=5)
        
        gen_report_button = ttk.Button(controls_frame, text="Generate Report (PDF)", command=self.placeholder_action)
        gen_report_button.pack(side=tk.LEFT, padx=5)
        
        download_log_button = ttk.Button(controls_frame, text="Download Full Log (CSV)", command=self.placeholder_action)
        download_log_button.pack(side=tk.LEFT, padx=5)
        
        delete_log_button = ttk.Button(controls_frame, text="Delete Log", command=self.placeholder_action)
        delete_log_button.pack(side=tk.LEFT, padx=5)

        search_frame = ttk.LabelFrame(self.logs_tab, text="Search Logs", padding="10")
        search_frame.pack(fill=tk.X, pady=5)
        
        search_label = ttk.Label(search_frame, text="Search Term (e.g., IP):")
        search_label.pack(side=tk.LEFT, padx=5)
        
        self.search_entry = ttk.Entry(search_frame, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        search_button = ttk.Button(search_frame, text="Search", command=self.placeholder_action)
        search_button.pack(side=tk.LEFT, padx=5)
        
        log_view_frame = ttk.LabelFrame(self.logs_tab, text="Log Viewer", padding="10")
        log_view_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        log_text = scrolledtext.ScrolledText(log_view_frame, wrap=tk.WORD, state=tk.DISABLED)
        log_text.pack(fill=tk.BOTH, expand=True)
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, "Log & Report generation is a complex backend feature.\n\n")
        log_text.insert(tk.END, "This tab is a placeholder for search results and log management.")
        log_text.config(state=tk.DISABLED)
    
    def placeholder_action(self):
        messagebox.showinfo("Feature Not Implemented", "This is a placeholder. Building the backend for reporting and log search is the next big step!")

    # --- GUI Actions & API Calls ---
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.running = False
            self.root.destroy()

    def start_sniffer(self):
        try:
            requests.get(f"{FLASK_API_URL}/start", timeout=3)
            messagebox.showinfo("Status", "Sniffer start request sent.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to Flask server: {e}")

    def stop_sniffer(self):
        try:
            requests.get(f"{FLASK_API_URL}/stop", timeout=3)
            messagebox.showinfo("Status", "Sniffer stop request sent.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to Flask server: {e}")

    def manual_block_ip(self):
        ip = simpledialog.askstring("Manual Block", "Enter the IP address to block:", parent=self.root)
        if ip:
            try:
                response = requests.post(f"{FLASK_API_URL}/blocking/block_ip", json={"ip": ip}, timeout=3)
                if response.status_code == 200:
                    messagebox.showinfo("Success", f"IP {ip} blocked successfully.")
                    self.data_queue.put(("refresh_blocked_list", True))
                else:
                    messagebox.showerror("Error", f"Failed to block IP: {response.json().get('message')}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not connect to Flask server: {e}")

    def unblock_selected_ip(self):
        selected_item = self.blocked_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an IP from the 'Blocked IPs' list to unblock.", parent=self.root)
            return
            
        item_values = self.blocked_tree.item(selected_item, 'values')
        ip_to_unblock = item_values[0]
        
        if not ip_to_unblock:
            messagebox.showerror("Error", "Could not read the IP from the selected row.")
            return

        if not messagebox.askyesno("Confirm Unblock", f"Are you sure you want to unblock {ip_to_unblock}?", parent=self.root):
            return
            
        try:
            response = requests.post(f"{FLASK_API_URL}/blocking/unblock_ip", json={"ip": ip_to_unblock}, timeout=3)
            if response.status_code == 200:
                messagebox.showinfo("Success", f"IP {ip_to_unblock} unblocked successfully.")
                self.data_queue.put(("refresh_blocked_list", True))
            else:
                messagebox.showerror("Error", f"Failed to unblock IP: {response.json().get('message')}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to Flask server: {e}")

    def toggle_autoblock(self):
        is_enabled = self.auto_block_var.get()
        try:
            requests.post(f"{FLASK_API_URL}/blocking/toggle_autoblock", json={"enabled": is_enabled}, timeout=3)
            status = "ENABLED" if is_enabled else "DISABLED"
            messagebox.showinfo("Status", f"Auto-Block is now {status}.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to Flask server: {e}")

    # --- Background Polling & Queue Processing ---
    def poll_backend_data(self):
        while self.running:
            try:
                status_data = requests.get(f"{FLASK_API_URL}/status", timeout=2).json()
                counts_data = requests.get(f"{FLASK_API_URL}/stats/counts", timeout=2).json()
                alerts_data = requests.get(f"{FLASK_API_URL}/alerts", timeout=2).json()
                graph_data = requests.get(f"{FLASK_API_URL}/stats/graph", timeout=2).json()
                blocked_data = requests.get(f"{FLASK_API_URL}/blocking/list", timeout=2).json()

                self.data_queue.put(("status", status_data))
                self.data_queue.put(("counts", counts_data))
                self.data_queue.put(("alerts", alerts_data))
                self.data_queue.put(("graph", graph_data))
                self.data_queue.put(("blocked_list", blocked_data))

            except requests.ConnectionError:
                self.data_queue.put(("status", {"sniffer_active": False, "error": "disconnected"}))
            except requests.Timeout:
                pass
            except Exception as e:
                print(f"Polling error: {e}")
            
            time.sleep(3)

    def process_gui_queue(self):
        try:
            while not self.data_queue.empty():
                data_type, data = self.data_queue.get_nowait()
                
                if data_type == "status":
                    self.render_status(data)
                elif data_type == "counts":
                    self.render_counts(data)
                elif data_type == "alerts":
                    self.render_alerts_tree(data)
                elif data_type == "graph":
                    self.render_graph(data)
                elif data_type == "blocked_list":
                    self.render_blocked_tree(data)
                elif data_type == "refresh_blocked_list":
                    try:
                        blocked_data = requests.get(f"{FLASK_API_URL}/blocking/list").json()
                        self.data_queue.put(("blocked_list", blocked_data))
                    except Exception as e:
                        print(f"Error on manual refresh: {e}")

        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_gui_queue)

    # --- GUI Render Functions (Main Thread) ---
    def render_status(self, data):
        if data.get("error") == "disconnected":
            self.status_label.config(text="Status: DISCONNECTED", foreground="orange")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return

        is_active = data.get('sniffer_active', False)
        if is_active:
            self.status_label.config(text="Status: RUNNING", foreground="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            self.status_label.config(text="Status: STOPPED", foreground="red")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def render_counts(self, data):
        self.packet_count_label.config(text=f"Packets: {data.get('packet_count', 0)}")
        self.alert_count_label.config(text=f"Alerts: {data.get('alert_count', 0)}")

    def render_alerts_tree(self, data):
        for i in self.alert_tree.get_children():
            self.alert_tree.delete(i)
        for alert in data:
            self.alert_tree.insert("", "end", values=(
                alert['timestamp'], 
                alert['alert_type'], 
                alert['source_ip'], 
                alert['dest_ip']
            ))

    def render_blocked_tree(self, data):
        for i in self.blocked_tree.get_children():
            self.blocked_tree.delete(i)
        for ip_data in data:
            self.blocked_tree.insert("", "end", values=(
                ip_data['ip_address'], 
                ip_data['timestamp'], 
                ip_data['reason']
            ))

    # --- THIS IS THE UPDATED GRAPH FUNCTION ---
    def render_graph(self, data):
        """Renders the line graph for alerts over time."""
        self.ax.clear()
        
        # --- Y-AXIS: Set minimum upper limit to 50 ---
        min_y_limit = 50 
        max_y_limit = min_y_limit # Default to the minimum
        # ---------------------------------------------
        
        if data:
            try:
                times_str = [item['time_minute'] for item in data]
                counts = [item['count'] for item in data]
                times_obj = [datetime.strptime(t, '%Y-%m-%d %H:%M') for t in times_str]
                
                if times_obj:
                    self.ax.plot(times_obj, counts, marker='o', linestyle='-', color='#007acc')
                    
                    # --- Y-AXIS: Calculate max Y and set ticks ---
                    max_val = max(counts)
                    # Round up to the nearest 5
                    data_limit = math.ceil(max_val / 5) * 5
                    # Use the data limit OR the minimum limit, whichever is higher
                    max_y_limit = max(min_y_limit, data_limit) 
                    # ---------------------------------------------
                    
                    # --- X-AXIS: Set format and 1-minute locator ---
                    self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                    self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
                    self.fig.autofmt_xdate(rotation=45, ha='right')
                    # ------------------------------------------------
                else:
                    self.ax.text(0.5, 0.5, "No alert data (last 30 mins)", 
                                 horizontalalignment='center', 
                                 verticalalignment='center', 
                                 transform=self.ax.transAxes)
            
            except Exception as e:
                print(f"Error rendering graph: {e}")
                self.ax.text(0.5, 0.5, "Error rendering graph data", 
                             horizontalalignment='center', 
                             transform=self.ax.transAxes)
        else:
            self.ax.text(0.5, 0.5, "No alert data (last 30 mins)", 
                         horizontalalignment='center', 
                         verticalalignment='center', 
                         transform=self.ax.transAxes)
        
        # --- APPLY AXIS FORMATTING ---
        self.ax.set_ylim(bottom=0, top=max_y_limit) # Force Y-limit
        self.ax.yaxis.set_major_locator(mticker.MultipleLocator(5)) # Ticks at 0, 5, 10... 50
        self.ax.set_ylabel('Alert Count')
        self.ax.set_xlabel('Time (Last 30 Minutes)')
        self.ax.set_title('Alerts per Minute')
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.fig.tight_layout()
        self.canvas.draw()
    # ------------------------------------------


if __name__ == "__main__":
    root = tk.Tk()
    app = IDPS_GUI(root)
    root.mainloop()