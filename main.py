import requests
from colorama import Fore, Style, init
import threading
import time
import json
import csv
import os
from datetime import datetime
import queue

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:
    tk = None  # Fallback to CLI if Tkinter unavailable

# Optional speed test
try:
    import speedtest
except ImportError:
    speedtest = None  # Will notify user

# Initialize colorama
init(autoreset=True)

HISTORY_FILE = "ip_history.json"
POLL_INTERVAL_SEC = 60  # IP change detection interval

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history(entry):
    history = load_history()
    history.append(entry)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass

def get_ip_info(ip_version="ipv4"):
    """
    Fetch IP information from ipapi.co API.
    Fallback: Uses ipinfo.io if ipapi.co rate limits or fails.
    """
    try:
        url = f"https://ipapi.co/{ip_version}/json/"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            data["source"] = "ipapi.co"
            return {
                "Source": data["source"],
                "IP Version": ip_version.upper(),
                "IP Address": data.get("ip", "N/A"),
                "City": data.get("city", "N/A"),
                "Region": data.get("region", "N/A"),
                "Country": data.get("country_name", "N/A"),
                "Country Code": data.get("country_code", "N/A"),
                "ISP": data.get("org", "N/A"),
                "ASN": data.get("asn", "N/A"),
                "Timestamp": datetime.utcnow().isoformat() + "Z"
            }

        elif response.status_code == 429:
            fallback_url = "https://ipinfo.io/json"
            fb_response = requests.get(fallback_url, timeout=5)
            if fb_response.status_code == 200:
                fb_data = fb_response.json()
                fb_data["source"] = "ipinfo.io"
                return {
                    "Source": fb_data["source"],
                    "IP Version": ip_version.upper(),
                    "IP Address": fb_data.get("ip", "N/A"),
                    "City": fb_data.get("city", "N/A"),
                    "Region": fb_data.get("region", "N/A"),
                    "Country": fb_data.get("country", "N/A"),
                    "Country Code": fb_data.get("country", "N/A"),
                    "ISP": fb_data.get("org", "N/A"),
                    "ASN": fb_data.get("asn", "N/A"),
                    "Timestamp": datetime.utcnow().isoformat() + "Z"
                }
            else:
                return None
        else:
            return None

    except requests.RequestException:
        return None

def detect_ipv6_only():
    ipv4 = get_ip_info("ipv4")
    ipv6 = get_ip_info("ipv6")
    ipv6_only = ipv6 and not ipv4
    return ipv4, ipv6, ipv6_only

def display_info(ip_data):
    """Console display fallback."""
    if ip_data:
        print(Fore.CYAN + "\n" + "=" * 40)
        print(Fore.GREEN + f"{ip_data['IP Version']} Information (Source: {ip_data['Source']})")
        print(Fore.CYAN + "=" * 40)
        for key, value in ip_data.items():
            if key not in ["Source", "IP Version"]:
                print(Fore.WHITE + f"{key}: {value}")
        print(Fore.CYAN + "=" * 40 + "\n")
    else:
        print(Fore.RED + "No information available.")

class IpApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IPv4 / IPv6 Information")
        self.root.geometry("820x520")
        self.root.resizable(False, False)

        self.queue = queue.Queue()
        self.current_ipv4 = None
        self.current_ipv6 = None
        self.last_seen_ips = {"ipv4": None, "ipv6": None}
        self.ipv6_only = False

        self.build_ui()
        self.refresh_data(initial=True)
        self.start_polling_thread()

    def build_ui(self):
        top_frame = ttk.Frame(self.root, padding=8)
        top_frame.pack(fill="x")

        self.status_label = ttk.Label(top_frame, text="Status: Ready")
        self.status_label.pack(side="left")

        self.ipv6_only_label = ttk.Label(top_frame, foreground="red")
        self.ipv6_only_label.pack(side="right")

        btn_frame = ttk.Frame(self.root, padding=8)
        btn_frame.pack(fill="x")

        ttk.Button(btn_frame, text="Refresh", command=self.refresh_data).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Export Text", command=self.export_text).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Speed Test", command=self.run_speed_test).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="View History", command=self.show_history_window).pack(side="left", padx=4)

        self.tree = ttk.Treeview(self.root, columns=("k", "v"), show="headings", height=18)
        self.tree.heading("k", text="Field")
        self.tree.heading("v", text="Value")
        self.tree.column("k", width=180)
        self.tree.column("v", width=600)
        self.tree.pack(fill="both", padx=8, pady=8)

        self.root.after(200, self.process_queue)

    def refresh_data(self, initial=False):
        self.status("Fetching IP data...")
        threading.Thread(target=self._fetch_data_worker, args=(initial,), daemon=True).start()

    def _fetch_data_worker(self, initial):
        ipv4, ipv6, ipv6_only = detect_ipv6_only()
        self.queue.put(("data", ipv4, ipv6, ipv6_only))

    def update_tree(self, ipv4, ipv6):
        self.tree.delete(*self.tree.get_children())
        combined = []
        if ipv4:
            combined.append(("--- IPv4 ---", ""))
            for k, v in ipv4.items():
                if k not in ["Timestamp"]:
                    combined.append((k, v))
        if ipv6:
            combined.append(("--- IPv6 ---", ""))
            for k, v in ipv6.items():
                if k not in ["Timestamp"]:
                    combined.append((k, v))
        for row in combined:
            self.tree.insert("", "end", values=row)

    def status(self, msg):
        self.status_label.config(text=f"Status: {msg}")

    def process_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if item[0] == "data":
                    _, ipv4, ipv6, ipv6_only = item
                    self.current_ipv4 = ipv4
                    self.current_ipv6 = ipv6
                    self.ipv6_only = ipv6_only
                    self.update_tree(ipv4, ipv6)
                    if ipv6_only:
                        self.ipv6_only_label.config(text="IPv6-ONLY ENVIRONMENT DETECTED")
                    else:
                        self.ipv6_only_label.config(text="")
                    self.status("Data refreshed")
                    self.handle_ip_change(ipv4, ipv6)
                    # Save history entries
                    if ipv4:
                        save_history({"type": "ipv4", **ipv4})
                    if ipv6:
                        save_history({"type": "ipv6", **ipv6})
                elif item[0] == "speedtest":
                    _, result_text = item
                    messagebox.showinfo("Speed Test Result", result_text)
                    self.status("Speed test complete")
                elif item[0] == "error":
                    _, msg = item
                    messagebox.showerror("Error", msg)
                    self.status("Error")
        except queue.Empty:
            pass
        self.root.after(500, self.process_queue)

    def export_text(self):
        if not (self.current_ipv4 or self.current_ipv6):
            messagebox.showwarning("Export", "No data to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            if self.current_ipv4:
                f.write("=== IPv4 ===\n")
                for k, v in self.current_ipv4.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
            if self.current_ipv6:
                f.write("=== IPv6 ===\n")
                for k, v in self.current_ipv6.items():
                    f.write(f"{k}: {v}\n")
        self.status("Exported text")

    def export_csv(self):
        if not (self.current_ipv4 or self.current_ipv6):
            messagebox.showwarning("Export", "No data to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        rows = []
        if self.current_ipv4:
            rows.append({"Family": "IPv4", **self.current_ipv4})
        if self.current_ipv6:
            rows.append({"Family": "IPv6", **self.current_ipv6})
        fieldnames = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        self.status("Exported CSV")

    def run_speed_test(self):
        if speedtest is None:
            messagebox.showwarning("Speed Test", "speedtest-cli not installed.\nInstall with: pip install speedtest-cli")
            return
        self.status("Running speed test...")
        threading.Thread(target=self._speed_worker, daemon=True).start()

    def _speed_worker(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            dl = st.download() / 1_000_000
            ul = st.upload() / 1_000_000
            ping = st.results.ping
            txt = f"Download: {dl:.2f} Mbps\nUpload: {ul:.2f} Mbps\nPing: {ping:.2f} ms"
            self.queue.put(("speedtest", txt))
        except Exception as e:
            self.queue.put(("error", f"Speed test failed: {e}"))

    def handle_ip_change(self, ipv4, ipv6):
        changed = []
        if ipv4 and ipv4["IP Address"] != self.last_seen_ips["ipv4"]:
            if self.last_seen_ips["ipv4"] is not None:
                changed.append(f"IPv4 changed: {self.last_seen_ips['ipv4']} -> {ipv4['IP Address']}")
            self.last_seen_ips["ipv4"] = ipv4["IP Address"]
        if ipv6 and ipv6["IP Address"] != self.last_seen_ips["ipv6"]:
            if self.last_seen_ips["ipv6"] is not None:
                changed.append(f"IPv6 changed: {self.last_seen_ips['ipv6']} -> {ipv6['IP Address']}")
            self.last_seen_ips["ipv6"] = ipv6["IP Address"]
        if changed:
            messagebox.showinfo("IP Change Detected", "\n".join(changed))

    def start_polling_thread(self):
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def _poll_loop(self):
        while True:
            time.sleep(POLL_INTERVAL_SEC)
            self.refresh_data()

    def show_history_window(self):
        history = load_history()
        win = tk.Toplevel(self.root)
        win.title("IP History")
        win.geometry("700x400")
        tv = ttk.Treeview(win, columns=("type", "ip", "city", "country", "asn", "timestamp"), show="headings")
        for col, text, w in [
            ("type", "Type", 60),
            ("ip", "IP Address", 160),
            ("city", "City", 110),
            ("country", "Country", 110),
            ("asn", "ASN", 80),
            ("timestamp", "Timestamp", 160),
        ]:
            tv.heading(col, text=text)
            tv.column(col, width=w)
        for entry in history[-200:]:
            tv.insert("", "end", values=(
                entry.get("type",""),
                entry.get("IP Address",""),
                entry.get("City",""),
                entry.get("Country",""),
                entry.get("ASN",""),
                entry.get("Timestamp",""),
            ))
        tv.pack(fill="both", expand=True, padx=6, pady=6)

def main_cli():
    print(Fore.MAGENTA + Style.BRIGHT + "🌐 IPv4/IPv6 Address Information App\n")
    ipv4_info = get_ip_info("ipv4")
    display_info(ipv4_info)
    ipv6_info = get_ip_info("ipv6")
    display_info(ipv6_info)
    print(Fore.GREEN + "✅ Data successfully retrieved and displayed.\n")

def main():
    # If Tkinter available, run GUI; else fallback to CLI
    if tk:
        root = tk.Tk()
        IpApp(root)
        root.mainloop()
    else:
        main_cli()

if __name__ == "__main__":
    main()
