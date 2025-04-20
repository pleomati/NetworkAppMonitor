import subprocess
import re
import psutil
import time
from datetime import datetime
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import csv
import pystray
from PIL import Image, ImageTk
import io
import sys
import ctypes
import platform
import pyperclip
import json
from tkinter import font as tkfont

class Translation:
    def __init__(self):
        self.languages = {
            'EN': {
                'app_title': "Network Connection Monitor",
                'menu_file': "File",
                'menu_language': "Language",
                'menu_exit': "Exit",
                'start_monitoring': "Start",
                'stop_monitoring': "Stop",
                'interval_label': "Interval (s):",
                'enable_logging': "Enable Logging",
                'disable_logging': "Disable Logging",
                'clear_results': "Clear",
                'block_ip': "Block IP",
                'unblock_ip': "Unblock IP",
                'block_app': "Block App",
                'unblock_app': "Unblock App",
                'copy_ip': "Copy IP",
                'copy_app': "Copy Name",
                'copy_path': "Copy Path",
                'blocked_ips': "Blocked IPs",
                'blocked_apps': "Blocked Apps",
                'status_ready': "Ready to start monitoring",
                'status_monitoring': "Monitoring active connections...",
                'status_stopped': "Monitoring stopped",
                'status_cleared': "Results cleared",
                'confirm_block_ip': "Are you sure you want to block IP {}?",
                'confirm_unblock_ip': "Are you sure you want to unblock IP {}?",
                'confirm_block_app': "Are you sure you want to block application:\n{}?",
                'confirm_unblock_app': "Are you sure you want to unblock application:\n{}?",
                'success_block_ip': "IP {} has been blocked",
                'success_unblock_ip': "IP {} has been unblocked",
                'success_block_app': "Application has been blocked",
                'success_unblock_app': "Application has been unblocked",
                'error_block_ip': "Failed to block IP {}",
                'error_unblock_ip': "Failed to unblock IP {}",
                'error_block_app': "Failed to block application",
                'error_unblock_app': "Failed to unblock application",
                'error_admin': "This program requires administrator privileges to block IPs and applications. Please restart as administrator.",
                'error_file_not_found': "File not found: {}",
                'error_process_info': "Could not get process information: {}",
                'error_clipboard': "Failed to copy to clipboard: {}",
                'error_interval': "Please enter a valid interval (number greater than 0)",
                'logging_enabled': "Data will be saved to file: {}",
                'logging_disabled': "Logging to file stopped",
                'col_detection_time': "Detection Time",
                'col_remote_ip': "Remote IP",
                'col_port': "Port",
                'col_pid': "PID",
                'col_process_name': "Process Name",
                'col_log_status': "Log Status",
                'col_block_status': "Block Status",
                'log_status_saved': "Saved",
                'log_status_error': "Error: {}",
                'log_status_not_saved': "Not saved",
                'block_status_blocked_ip': "Blocked (IP)",
                'block_status_blocked_app': "Blocked (App)",
                'block_status_unblocked': "Unblocked",
                'unknown_process': "Unknown process",
                'tray_show': "Show",
                'tray_exit': "Exit",
                'tray_title': "Network Connection Monitor"
            },
            'PL': {
                'app_title': "Monitor Połączeń Sieciowych",
                'menu_file': "Plik",
                'menu_language': "Język",
                'menu_exit': "Zakończ",
                'start_monitoring': "Start",
                'stop_monitoring': "Stop",
                'interval_label': "Interwał (s):",
                'enable_logging': "Włącz logowanie",
                'disable_logging': "Wyłącz logowanie",
                'clear_results': "Wyczyść",
                'block_ip': "Zablokuj IP",
                'unblock_ip': "Odblokuj IP",
                'block_app': "Zablokuj aplikację",
                'unblock_app': "Odblokuj aplikację",
                'copy_ip': "Kopiuj IP",
                'copy_app': "Kopiuj nazwę",
                'copy_path': "Kopiuj ścieżkę",
                'blocked_ips': "Zablokowane adresy IP",
                'blocked_apps': "Zablokowane aplikacje",
                'status_ready': "Gotowy do rozpoczęcia monitorowania",
                'status_monitoring': "Monitorowanie aktywnych połączeń...",
                'status_stopped': "Monitorowanie zatrzymane",
                'status_cleared': "Wyniki wyczyszczone",
                'confirm_block_ip': "Czy na pewno chcesz zablokować adres {}?",
                'confirm_unblock_ip': "Czy na pewno chcesz odblokować adres {}?",
                'confirm_block_app': "Czy na pewno chcesz zablokować aplikację:\n{}?",
                'confirm_unblock_app': "Czy na pewno chcesz odblokować aplikację:\n{}?",
                'success_block_ip': "Adres {} został zablokowany",
                'success_unblock_ip': "Adres {} został odblokowany",
                'success_block_app': "Aplikacja została zablokowana",
                'success_unblock_app': "Aplikacja została odblokowana",
                'error_block_ip': "Nie udało się zablokować adresu {}",
                'error_unblock_ip': "Nie udało się odblokować adresu {}",
                'error_block_app': "Nie udało się zablokować aplikacji",
                'error_unblock_app': "Nie udało się odblokować aplikacji",
                'error_admin': "Program wymaga uprawnień administratora do blokowania IP i aplikacji. Uruchom program ponownie jako administrator.",
                'error_file_not_found': "Nie znaleziono pliku: {}",
                'error_process_info': "Nie można uzyskać informacji o procesie: {}",
                'error_clipboard': "Nie udało się skopiować do schowka: {}",
                'error_interval': "Proszę podać prawidłowy interwał (liczba większa od 0)",
                'logging_enabled': "Dane będą zapisywane do pliku: {}",
                'logging_disabled': "Zatrzymano zapis do pliku logu",
                'col_detection_time': "Data i czas wykrycia",
                'col_remote_ip': "Zdalne IP",
                'col_port': "Port",
                'col_pid': "PID",
                'col_process_name': "Nazwa Procesu",
                'col_log_status': "Status logu",
                'col_block_status': "Status blokady",
                'log_status_saved': "Zapisano",
                'log_status_error': "Błąd: {}",
                'log_status_not_saved': "Nie zapisano",
                'block_status_blocked_ip': "Zablokowany (IP)",
                'block_status_blocked_app': "Zablokowany (App)",
                'block_status_unblocked': "Odblokowany",
                'unknown_process': "Nieznany proces",
                'tray_show': "Pokaż",
                'tray_exit': "Zakończ",
                'tray_title': "Monitor Połączeń Sieciowych"
            }
        }
        self.current_lang = 'EN'  # Domyślny język: angielski

    def get(self, key):
        return self.languages[self.current_lang].get(key, key)

    def set_language(self, lang):
        if lang in self.languages:
            self.current_lang = lang
        return self.get

tr = Translation()

class ConnectionMonitor:
    def __init__(self):
        self.known_connections = set()
        self.process_cache = {}
        self.blocked_ips = set()
        self.blocked_apps = set()  # Stores full paths to .exe files
        self.blocked_ips_file = "blocked_ips.json"
        self.blocked_apps_file = "blocked_apps.json"
        self.load_blocked_ips()
        self.load_blocked_apps()
        
    def save_blocked_ips(self):
        try:
            with open(self.blocked_ips_file, 'w') as f:
                json.dump(list(self.blocked_ips), f)
        except Exception as e:
            print(f"Error saving blocked IPs: {e}")

    def save_blocked_apps(self):
        try:
            with open(self.blocked_apps_file, 'w') as f:
                json.dump(list(self.blocked_apps), f)
        except Exception as e:
            print(f"Error saving blocked apps: {e}")

    def load_blocked_ips(self):
        try:
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    ips = json.load(f)
                    self.blocked_ips.update(ips)
        except Exception as e:
            print(f"Error loading blocked IPs: {e}")

    def load_blocked_apps(self):
        try:
            if os.path.exists(self.blocked_apps_file):
                with open(self.blocked_apps_file, 'r') as f:
                    apps = json.load(f)
                    # Check if apps still exist
                    valid_apps = {app for app in apps if os.path.exists(app)}
                    self.blocked_apps.update(valid_apps)
        except Exception as e:
            print(f"Error loading blocked apps: {e}")

    def validate_ip(self, ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def get_process_info(self, pid):
        if pid in self.process_cache:
            return self.process_cache[pid]
        
        try:
            process = psutil.Process(pid)
            name = process.name()
            exe_path = process.exe() or ""
            self.process_cache[pid] = (name, exe_path)
            return (name, exe_path)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return (tr.get('unknown_process'), "")

    def split_address(self, address):
        if ':' in address:
            ip, port = address.rsplit(':', 1)
            ip = ip.replace('[', '').replace(']', '')
            return ip, port
        return address, ""

    def get_current_connections(self):
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, check=True)
        lines = result.stdout.split('\n')
        local_pattern = re.compile(r'127\.0\.0\.1|\[::1\]')
        current_connections = set()

        for line in lines:
            if "ESTABLISHED" in line:
                parts = list(filter(None, line.split()))
                if len(parts) >= 4:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    
                    if not local_pattern.search(local_addr):
                        pid = int(parts[-1])
                        remote_ip, remote_port = self.split_address(remote_addr)
                        process_name, exe_path = self.get_process_info(pid)
                        current_connections.add((remote_ip, remote_port, pid, process_name, exe_path))

        return current_connections
    
    def block_ip(self, ip):
        if platform.system() == 'Windows':
            try:
                rule_name_in = f"Block_IP_In_{ip.replace('.', '_').replace(':', '_')}"
                rule_name_out = f"Block_IP_Out_{ip.replace('.', '_').replace(':', '_')}"
                
                # Check if rules already exist
                result_in = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name_in}'], 
                    capture_output=True, text=True, shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                result_out = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name_out}'], 
                    capture_output=True, text=True, shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Add rules if they don't exist
                if 'No rules' in result_in.stdout or 'Nie znaleziono' in result_in.stdout:
                    result = subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                         f'name={rule_name_in}', 'dir=in', 'action=block',
                         f'remoteip={ip}', 'enable=yes', 'protocol=any'],
                        capture_output=True, text=True,
                        shell=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if result.returncode != 0:
                        print(f"Error adding inbound rule: {result.stderr}")
                        return False
                
                if 'No rules' in result_out.stdout or 'Nie znaleziono' in result_out.stdout:
                    result = subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                         f'name={rule_name_out}', 'dir=out', 'action=block',
                         f'remoteip={ip}', 'enable=yes', 'protocol=any'],
                        capture_output=True, text=True,
                        shell=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if result.returncode != 0:
                        print(f"Error adding outbound rule: {result.stderr}")
                        return False
                
                self.blocked_ips.add(ip)
                self.save_blocked_ips()
                return True
                
            except subprocess.CalledProcessError as e:
                error_msg = f"Error blocking IP {ip}: {e.stderr if e.stderr else str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
            except Exception as e:
                error_msg = f"Unexpected error blocking IP {ip}: {str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
        else:
            messagebox.showwarning(tr.get('block_ip'), tr.get('error_admin'))
            return False
    
    def unblock_ip(self, ip):
        if platform.system() == 'Windows':
            try:
                rule_name_in = f"Block_IP_In_{ip.replace('.', '_').replace(':', '_')}"
                rule_name_out = f"Block_IP_Out_{ip.replace('.', '_').replace(':', '_')}"
                
                success = True
                
                # Remove inbound rule
                result_in = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name={rule_name_in}'],
                    capture_output=True, text=True,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result_in.returncode != 0:
                    if "No rules" not in result_in.stderr and "Nie znaleziono" not in result_in.stderr:
                        print(f"Error removing inbound rule: {result_in.stderr}")
                        success = False
                
                # Remove outbound rule
                result_out = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name={rule_name_out}'],
                    capture_output=True, text=True,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result_out.returncode != 0:
                    if "No rules" not in result_out.stderr and "Nie znaleziono" not in result_out.stderr:
                        print(f"Error removing outbound rule: {result_out.stderr}")
                        success = False
                
                if success:
                    self.blocked_ips.discard(ip)
                    self.save_blocked_ips()
                    return True
                else:
                    error_msg = f"Failed to remove all rules for IP {ip}"
                    print(error_msg)
                    messagebox.showerror("Error", error_msg)
                    return False
                    
            except subprocess.CalledProcessError as e:
                error_msg = f"Error unblocking IP {ip}: {e.stderr if e.stderr else str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
            except Exception as e:
                error_msg = f"Unexpected error unblocking IP {ip}: {str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
        else:
            messagebox.showwarning(tr.get('unblock_ip'), tr.get('error_admin'))
            return False

    def block_app(self, exe_path):
        if platform.system() == 'Windows':
            try:
                if not os.path.exists(exe_path):
                    messagebox.showerror("Error", tr.get('error_file_not_found').format(exe_path))
                    return False
                    
                # Get filename without path
                app_name = os.path.basename(exe_path)
                
                # Clean rule names
                rule_name_in = f"Block_App_In_{app_name.replace('.exe', '').replace(' ', '_')}"
                rule_name_out = f"Block_App_Out_{app_name.replace('.exe', '').replace(' ', '_')}"
                
                # Check if rules already exist
                result_in = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name_in}'], 
                    capture_output=True, text=True, shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                result_out = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name_out}'], 
                    capture_output=True, text=True, shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Add rules if they don't exist
                if 'No rules' in result_in.stdout or 'Nie znaleziono' in result_in.stdout:
                    result = subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                         f'name={rule_name_in}', 'dir=in', 'action=block',
                         f'program={exe_path}', 'enable=yes', 'protocol=any'],
                        capture_output=True, text=True,
                        shell=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if result.returncode != 0:
                        print(f"Error adding inbound app rule: {result.stderr}")
                        return False
                
                if 'No rules' in result_out.stdout or 'Nie znaleziono' in result_out.stdout:
                    result = subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                         f'name={rule_name_out}', 'dir=out', 'action=block',
                         f'program={exe_path}', 'enable=yes', 'protocol=any'],
                        capture_output=True, text=True,
                        shell=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if result.returncode != 0:
                        print(f"Error adding outbound app rule: {result.stderr}")
                        return False
                
                self.blocked_apps.add(exe_path)
                self.save_blocked_apps()
                return True
                
            except subprocess.CalledProcessError as e:
                error_msg = f"Error blocking app {exe_path}: {e.stderr if e.stderr else str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
            except Exception as e:
                error_msg = f"Unexpected error blocking app {exe_path}: {str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
        else:
            messagebox.showwarning(tr.get('block_app'), tr.get('error_admin'))
            return False
    
    def unblock_app(self, exe_path):
        if platform.system() == 'Windows':
            try:
                app_name = os.path.basename(exe_path)
                rule_name_in = f"Block_App_In_{app_name.replace('.exe', '').replace(' ', '_')}"
                rule_name_out = f"Block_App_Out_{app_name.replace('.exe', '').replace(' ', '_')}"
                
                success = True
                
                # Remove inbound rule
                result_in = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name={rule_name_in}'],
                    capture_output=True, text=True,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result_in.returncode != 0:
                    if "No rules" not in result_in.stderr and "Nie znaleziono" not in result_in.stderr:
                        print(f"Error removing inbound app rule: {result_in.stderr}")
                        success = False
                
                # Remove outbound rule
                result_out = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name={rule_name_out}'],
                    capture_output=True, text=True,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result_out.returncode != 0:
                    if "No rules" not in result_out.stderr and "Nie znaleziono" not in result_out.stderr:
                        print(f"Error removing outbound app rule: {result_out.stderr}")
                        success = False
                
                if success:
                    self.blocked_apps.discard(exe_path)
                    self.save_blocked_apps()
                    return True
                else:
                    error_msg = f"Failed to remove all rules for app {exe_path}"
                    print(error_msg)
                    messagebox.showerror("Error", error_msg)
                    return False
                    
            except subprocess.CalledProcessError as e:
                error_msg = f"Error unblocking app {exe_path}: {e.stderr if e.stderr else str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
            except Exception as e:
                error_msg = f"Unexpected error unblocking app {exe_path}: {str(e)}"
                print(error_msg)
                messagebox.showerror("Error", error_msg)
                return False
        else:
            messagebox.showwarning(tr.get('unblock_app'), tr.get('error_admin'))
            return False

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        
        if sys.platform == 'win32':
            myappid = 'network.monitor.app.1.0'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        
        self.set_window_icon()
        self.root.title(tr.get('app_title'))
        self.root.geometry("1200x800")
        
        # Configure styles
        self.configure_styles()
        
        self.monitor = ConnectionMonitor()
        self.is_monitoring = False
        self.update_interval = 1
        self.log_file = None
        self.logging_enabled = False
        
        self.tray_icon = None
        self.tray_menu = None
        self.setup_tray_icon()
        self.root.protocol('WM_DELETE_WINDOW', self.minimize_to_tray)
        
        self.setup_ui()
        self.setup_menu()
    
    def configure_styles(self):
        # Create a style object
        self.style = ttk.Style()
        
        # Configure the main window background
        self.root.configure(bg='#f0f0f0')
        
        # Configure theme
        if 'clam' in self.style.theme_names():
            self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('.', background='#f0f0f0', foreground='#333333')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', foreground='#333333')
        self.style.configure('TButton', 
                           background='#4a6ea9', 
                           foreground='white',
                           borderwidth=1,
                           focusthickness=3,
                           focuscolor='#4a6ea9')
        self.style.map('TButton',
                      background=[('active', '#3a5a8f'), ('pressed', '#2a4a7f')],
                      foreground=[('active', 'white'), ('pressed', 'white')])
        
        # Treeview style
        self.style.configure('Treeview',
                           background='white',
                           foreground='#333333',
                           fieldbackground='white',
                           rowheight=25)
        self.style.configure('Treeview.Heading',
                           background='#4a6ea9',
                           foreground='white',
                           padding=5,
                           font=('Segoe UI', 9, 'bold'))
        self.style.map('Treeview',
                      background=[('selected', '#4a6ea9')],
                      foreground=[('selected', 'white')])
        
        # Listbox style
        self.style.configure('TListbox',
                           background='white',
                           foreground='#333333',
                           selectbackground='#4a6ea9',
                           selectforeground='white')
        
        # Entry style
        self.style.configure('TEntry',
                           fieldbackground='white',
                           foreground='#333333',
                           insertcolor='#333333')
        
        # Status bar style
        self.style.configure('Status.TLabel',
                           background='#e0e0e0',
                           foreground='#333333',
                           relief=tk.SUNKEN,
                           padding=5)
        
        # LabelFrame style
        self.style.configure('TLabelframe',
                           background='#f0f0f0',
                           foreground='#333333')
        self.style.configure('TLabelframe.Label',
                           background='#f0f0f0',
                           foreground='#4a6ea9')
        
        # Configure fonts
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(size=9, family='Segoe UI')
        
        text_font = tkfont.nametofont("TkTextFont")
        text_font.configure(size=9, family='Segoe UI')
        
        fixed_font = tkfont.nametofont("TkFixedFont")
        fixed_font.configure(size=9, family='Consolas')

    def set_window_icon(self):
        try:
            icon_path = self.get_icon_path()
            if sys.platform == 'win32':
                self.root.iconbitmap(icon_path)
            img = Image.open(icon_path)
            img = img.resize((64, 64), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self.root.iconphoto(True, photo)
        except Exception as e:
            print(f"Error loading icon: {e}")
            img = Image.new('RGB', (64, 64), (70, 130, 180))
            photo = ImageTk.PhotoImage(img)
            self.root.iconphoto(True, photo)
    
    def get_icon_path(self):
        # Wbudowana ikona jako base64
        ICON_BASE64 = """PASTE_THE_GENERATED_BASE64_HERE"""
        
        try:
            icon_data = base64.b64decode(ICON_BASE64)
            with open("tmp_icon.ico", "wb") as f:
                f.write(icon_data)
            return "tmp_icon.ico"
        except:
            pass
        
        if os.path.exists("icon.ico"):
            return "icon.ico"
        
        img = Image.new('RGB', (64, 64), (70, 130, 180))
        img.save('tmp_icon.ico', format='ICO')
        return 'tmp_icon.ico'
    
    def setup_tray_icon(self):
        try:
            icon_path = self.get_icon_path()
            image = Image.open(icon_path)
        except:
            image = Image.new('RGB', (64, 64), (70, 130, 180))
        
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        self.tray_menu = pystray.Menu(
            pystray.MenuItem(tr.get('tray_show'), self.restore_from_tray),
            pystray.MenuItem(tr.get('tray_exit'), self.quit_program)
        )
        
        self.tray_icon = pystray.Icon(
            "network_monitor",
            icon=Image.open(io.BytesIO(img_byte_arr)),
            title=tr.get('tray_title'),
            menu=self.tray_menu
        )
    
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label=tr.get('menu_exit'), command=self.quit_program)
        menubar.add_cascade(label=tr.get('menu_file'), menu=file_menu)
        
        # Language menu
        lang_menu = tk.Menu(menubar, tearoff=0)
        lang_menu.add_command(label="English", command=lambda: self.change_language('EN'))
        lang_menu.add_command(label="Polski", command=lambda: self.change_language('PL'))
        menubar.add_cascade(label=tr.get('menu_language'), menu=lang_menu)
        
        self.root.config(menu=menubar)
    
    def change_language(self, lang):
        tr.set_language(lang)
        self.root.title(tr.get('app_title'))
        self.setup_menu()  # Refresh menu with new translations
        
        # Update UI elements
        self.start_btn.config(text=tr.get('start_monitoring'))
        self.stop_btn.config(text=tr.get('stop_monitoring'))
        self.interval_label.config(text=tr.get('interval_label'))
        self.log_btn.config(text=tr.get('enable_logging') if not self.logging_enabled else tr.get('disable_logging'))
        self.clear_btn.config(text=tr.get('clear_results'))
        
        self.block_ip_btn.config(text=tr.get('block_ip'))
        self.unblock_ip_btn.config(text=tr.get('unblock_ip'))
        self.block_app_btn.config(text=tr.get('block_app'))
        self.unblock_app_btn.config(text=tr.get('unblock_app'))
        self.copy_ip_btn.config(text=tr.get('copy_ip'))
        self.copy_app_btn.config(text=tr.get('copy_app'))
        self.copy_path_btn.config(text=tr.get('copy_path'))
        
        self.blocked_ip_frame.config(text=tr.get('blocked_ips'))
        self.blocked_app_frame.config(text=tr.get('blocked_apps'))
        
        # Update status
        if not self.is_monitoring:
            self.status_var.set(tr.get('status_ready'))
        else:
            self.status_var.set(tr.get('status_monitoring'))
        
        # Update column headers
        for col, text in [
            ("detection_time", tr.get('col_detection_time')),
            ("remote_ip", tr.get('col_remote_ip')),
            ("port", tr.get('col_port')),
            ("pid", tr.get('col_pid')),
            ("process_name", tr.get('col_process_name')),
            ("log_status", tr.get('col_log_status')),
            ("block_status", tr.get('col_block_status'))
        ]:
            self.tree.heading(col, text=text)
        
        # Update tray icon
        if self.tray_icon:
            self.tray_icon.title = tr.get('tray_title')
            self.tray_icon.menu = pystray.Menu(
                pystray.MenuItem(tr.get('tray_show'), self.restore_from_tray),
                pystray.MenuItem(tr.get('tray_exit'), self.quit_program)
            )
    
    def minimize_to_tray(self):
        self.root.withdraw()
        if not self.tray_icon._running:
            import threading
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
    
    def restore_from_tray(self, icon=None, item=None):
        self.tray_icon.stop()
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
    
    def quit_program(self, icon=None, item=None):
        self.stop_monitoring()
        if self.logging_enabled:
            self.close_log_file()
        
        if os.path.exists('tmp_icon.ico'):
            try:
                os.remove('tmp_icon.ico')
            except:
                pass
                
        self.root.destroy()
        if self.tray_icon:
            self.tray_icon.stop()
        sys.exit(0)
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text=tr.get('start_monitoring'), command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text=tr.get('stop_monitoring'), command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.interval_label = ttk.Label(control_frame, text=tr.get('interval_label'))
        self.interval_label.pack(side=tk.LEFT, padx=5)
        self.interval_entry = ttk.Entry(control_frame, width=5)
        self.interval_entry.insert(0, str(self.update_interval))
        self.interval_entry.pack(side=tk.LEFT, padx=5)
        
        self.log_btn = ttk.Button(control_frame, text=tr.get('enable_logging'), command=self.toggle_logging)
        self.log_btn.pack(side=tk.LEFT, padx=10)
        
        self.clear_btn = ttk.Button(control_frame, text=tr.get('clear_results'), command=self.clear_results)
        self.clear_btn.pack(side=tk.RIGHT, padx=5)
        
        # Main panel with table and lists
        main_panel = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        main_panel.pack(fill=tk.BOTH, expand=True)
        
        # Connection table panel
        table_frame = ttk.Frame(main_panel, padding=5)
        main_panel.add(table_frame, weight=2)
        
        columns = ("detection_time", "remote_ip", "port", "pid", "process_name", "log_status", "block_status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode='browse')
        
        # Set column headers
        for col, text in [
            ("detection_time", tr.get('col_detection_time')),
            ("remote_ip", tr.get('col_remote_ip')),
            ("port", tr.get('col_port')),
            ("pid", tr.get('col_pid')),
            ("process_name", tr.get('col_process_name')),
            ("log_status", tr.get('col_log_status')),
            ("block_status", tr.get('col_block_status'))
        ]:
            self.tree.heading(col, text=text)
        
        # Column widths
        self.tree.column("detection_time", width=150, anchor=tk.CENTER)
        self.tree.column("remote_ip", width=120, anchor=tk.CENTER)
        self.tree.column("port", width=60, anchor=tk.CENTER)
        self.tree.column("pid", width=60, anchor=tk.CENTER)
        self.tree.column("process_name", width=180)
        self.tree.column("log_status", width=80, anchor=tk.CENTER)
        self.tree.column("block_status", width=100, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Action buttons panel
        action_frame = ttk.Frame(table_frame, padding=(5, 0))
        action_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        button_options = {'width': 15, 'padding': (3, 3)}
        
        self.block_ip_btn = ttk.Button(action_frame, text=tr.get('block_ip'), 
                                     command=self.block_selected_ip, 
                                     state=tk.DISABLED, **button_options)
        self.block_ip_btn.pack(fill=tk.X, pady=2)
        
        self.unblock_ip_btn = ttk.Button(action_frame, text=tr.get('unblock_ip'), 
                                       command=self.unblock_selected_ip, 
                                       state=tk.DISABLED, **button_options)
        self.unblock_ip_btn.pack(fill=tk.X, pady=2)
        
        self.block_app_btn = ttk.Button(action_frame, text=tr.get('block_app'), 
                                      command=self.block_selected_app, 
                                      state=tk.DISABLED, **button_options)
        self.block_app_btn.pack(fill=tk.X, pady=2)
        
        self.unblock_app_btn = ttk.Button(action_frame, text=tr.get('unblock_app'), 
                                        command=self.unblock_selected_app, 
                                        state=tk.DISABLED, **button_options)
        self.unblock_app_btn.pack(fill=tk.X, pady=2)
        
        self.copy_ip_btn = ttk.Button(action_frame, text=tr.get('copy_ip'), 
                                    command=self.copy_selected_ip, 
                                    state=tk.DISABLED, **button_options)
        self.copy_ip_btn.pack(fill=tk.X, pady=2)
        
        self.copy_app_btn = ttk.Button(action_frame, text=tr.get('copy_app'), 
                                     command=self.copy_selected_app, 
                                     state=tk.DISABLED, **button_options)
        self.copy_app_btn.pack(fill=tk.X, pady=2)
        
        self.copy_path_btn = ttk.Button(action_frame, text=tr.get('copy_path'), 
                                      command=self.copy_selected_path, 
                                      state=tk.DISABLED, **button_options)
        self.copy_path_btn.pack(fill=tk.X, pady=2)
        
        # Blocked lists panel
        lists_frame = ttk.Frame(main_panel, padding=5)
        main_panel.add(lists_frame, weight=1)
        
        # Blocked IPs list
        self.blocked_ip_frame = ttk.LabelFrame(lists_frame, text=tr.get('blocked_ips'), padding=5)
        self.blocked_ip_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.blocked_ip_listbox = tk.Listbox(self.blocked_ip_frame, 
                                           font=('Consolas', 9),
                                           selectbackground='#4a6ea9',
                                           selectforeground='white')
        self.blocked_ip_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        blocked_ip_btn_frame = ttk.Frame(self.blocked_ip_frame)
        blocked_ip_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(blocked_ip_btn_frame, text=tr.get('copy_ip'), 
                  command=self.copy_blocked_ip, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(blocked_ip_btn_frame, text=tr.get('unblock_ip'), 
                  command=self.unblock_selected_ip_from_list, width=10).pack(side=tk.LEFT, padx=2)
        
        # Blocked apps list
        self.blocked_app_frame = ttk.LabelFrame(lists_frame, text=tr.get('blocked_apps'), padding=5)
        self.blocked_app_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.blocked_app_listbox = tk.Listbox(self.blocked_app_frame, 
                                            font=('Consolas', 9),
                                            selectbackground='#4a6ea9',
                                            selectforeground='white')
        self.blocked_app_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        blocked_app_btn_frame = ttk.Frame(self.blocked_app_frame)
        blocked_app_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(blocked_app_btn_frame, text=tr.get('copy_path'), 
                  command=self.copy_blocked_app, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(blocked_app_btn_frame, text=tr.get('unblock_app'), 
                  command=self.unblock_selected_app_from_list, width=10).pack(side=tk.LEFT, padx=2)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set(tr.get('status_ready'))
        status_bar = ttk.Label(self.root, textvariable=self.status_var, 
                             style='Status.TLabel')
        status_bar.pack(fill=tk.X, padx=0, pady=0)
        
        # Bind events
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        self.blocked_ip_listbox.bind('<<ListboxSelect>>', self.on_blocked_ip_list_select)
        self.blocked_app_listbox.bind('<<ListboxSelect>>', self.on_blocked_app_list_select)
        
        # Context menu
        self.setup_context_menu()
        
        # Update blocked lists
        self.update_blocked_lists()
    
    def setup_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label=tr.get('copy_ip'), command=self.copy_selected_ip)
        self.context_menu.add_command(label=tr.get('copy_app'), command=self.copy_selected_app)
        self.context_menu.add_command(label=tr.get('copy_path'), command=self.copy_selected_path)
        self.context_menu.add_separator()
        self.context_menu.add_command(label=tr.get('block_ip'), command=self.block_selected_ip)
        self.context_menu.add_command(label=tr.get('unblock_ip'), command=self.unblock_selected_ip)
        self.context_menu.add_separator()
        self.context_menu.add_command(label=tr.get('block_app'), command=self.block_selected_app)
        self.context_menu.add_command(label=tr.get('unblock_app'), command=self.unblock_selected_app)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            values = self.tree.item(item, 'values')
            ip = values[1]
            pid = values[3]
            
            # Get app path
            exe_path = ""
            try:
                process = psutil.Process(int(pid))
                exe_path = process.exe() or ""
            except:
                pass
            
            # Set menu item states
            self.context_menu.entryconfig(tr.get('block_ip'), 
                state=tk.NORMAL if ip not in self.monitor.blocked_ips else tk.DISABLED)
            self.context_menu.entryconfig(tr.get('unblock_ip'), 
                state=tk.NORMAL if ip in self.monitor.blocked_ips else tk.DISABLED)
            self.context_menu.entryconfig(tr.get('block_app'), 
                state=tk.NORMAL if exe_path and exe_path not in self.monitor.blocked_apps else tk.DISABLED)
            self.context_menu.entryconfig(tr.get('unblock_app'), 
                state=tk.NORMAL if exe_path and exe_path in self.monitor.blocked_apps else tk.DISABLED)
            self.context_menu.entryconfig(tr.get('copy_path'), 
                state=tk.NORMAL if exe_path else tk.DISABLED)
            
            self.context_menu.post(event.x_root, event.y_root)
    
    def on_tree_select(self, event):
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0], 'values')
            ip = values[1]
            pid = values[3]
            
            # Get app path
            exe_path = ""
            try:
                process = psutil.Process(int(pid))
                exe_path = process.exe() or ""
            except:
                pass
            
            # Set IP buttons state
            if ip in self.monitor.blocked_ips:
                self.block_ip_btn.config(state=tk.DISABLED)
                self.unblock_ip_btn.config(state=tk.NORMAL)
            else:
                self.block_ip_btn.config(state=tk.NORMAL)
                self.unblock_ip_btn.config(state=tk.DISABLED)
            
            # Set app buttons state
            if exe_path and exe_path in self.monitor.blocked_apps:
                self.block_app_btn.config(state=tk.DISABLED)
                self.unblock_app_btn.config(state=tk.NORMAL)
            elif exe_path:
                self.block_app_btn.config(state=tk.NORMAL)
                self.unblock_app_btn.config(state=tk.DISABLED)
            else:
                self.block_app_btn.config(state=tk.DISABLED)
                self.unblock_app_btn.config(state=tk.DISABLED)
            
            self.copy_ip_btn.config(state=tk.NORMAL)
            self.copy_app_btn.config(state=tk.NORMAL if values[4] != tr.get('unknown_process') else tk.DISABLED)
            self.copy_path_btn.config(state=tk.NORMAL if exe_path else tk.DISABLED)
        else:
            self.block_ip_btn.config(state=tk.DISABLED)
            self.unblock_ip_btn.config(state=tk.DISABLED)
            self.block_app_btn.config(state=tk.DISABLED)
            self.unblock_app_btn.config(state=tk.DISABLED)
            self.copy_ip_btn.config(state=tk.DISABLED)
            self.copy_app_btn.config(state=tk.DISABLED)
            self.copy_path_btn.config(state=tk.DISABLED)
    
    def on_blocked_ip_list_select(self, event):
        selected = self.blocked_ip_listbox.curselection()
        if selected:
            self.copy_ip_btn.config(state=tk.NORMAL)
        else:
            self.copy_ip_btn.config(state=tk.DISABLED)
    
    def on_blocked_app_list_select(self, event):
        selected = self.blocked_app_listbox.curselection()
        if selected:
            self.copy_path_btn.config(state=tk.NORMAL)
        else:
            self.copy_path_btn.config(state=tk.DISABLED)
    
    def copy_selected_ip(self):
        selected = self.tree.selection()
        if selected:
            ip = self.tree.item(selected[0], 'values')[1]
            self.copy_to_clipboard(ip)
    
    def copy_selected_app(self):
        selected = self.tree.selection()
        if selected:
            app_name = self.tree.item(selected[0], 'values')[4]
            self.copy_to_clipboard(app_name)
    
    def copy_selected_path(self):
        selected = self.tree.selection()
        if selected:
            pid = self.tree.item(selected[0], 'values')[3]
            try:
                process = psutil.Process(int(pid))
                exe_path = process.exe() or ""
                if exe_path:
                    self.copy_to_clipboard(exe_path)
            except:
                pass
    
    def copy_blocked_ip(self):
        selected = self.blocked_ip_listbox.curselection()
        if selected:
            ip = self.blocked_ip_listbox.get(selected[0])
            self.copy_to_clipboard(ip)
    
    def copy_blocked_app(self):
        selected = self.blocked_app_listbox.curselection()
        if selected:
            app_path = self.blocked_app_listbox.get(selected[0])
            self.copy_to_clipboard(app_path)
    
    def copy_to_clipboard(self, text):
        try:
            pyperclip.copy(text)
            self.status_var.set(f"Copied to clipboard: {text}" if tr.current_lang == 'EN' else f"Skopiowano do schowka: {text}")
        except Exception as e:
            messagebox.showerror("Error", tr.get('error_clipboard').format(str(e)))
    
    def block_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        ip = self.tree.item(selected[0], 'values')[1]
        if messagebox.askyesno(tr.get('block_ip'), tr.get('confirm_block_ip').format(ip)):
            if self.monitor.block_ip(ip):
                messagebox.showinfo(tr.get('block_ip'), tr.get('success_block_ip').format(ip))
                self.update_blocked_lists()
            else:
                messagebox.showerror(tr.get('block_ip'), tr.get('error_block_ip').format(ip))
    
    def unblock_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        ip = self.tree.item(selected[0], 'values')[1]
        if messagebox.askyesno(tr.get('unblock_ip'), tr.get('confirm_unblock_ip').format(ip)):
            if self.monitor.unblock_ip(ip):
                messagebox.showinfo(tr.get('unblock_ip'), tr.get('success_unblock_ip').format(ip))
                self.update_blocked_lists()
            else:
                messagebox.showerror(tr.get('unblock_ip'), tr.get('error_unblock_ip').format(ip))
    
    def unblock_selected_ip_from_list(self):
        selected = self.blocked_ip_listbox.curselection()
        if not selected:
            return
            
        ip = self.blocked_ip_listbox.get(selected[0])
        if messagebox.askyesno(tr.get('unblock_ip'), tr.get('confirm_unblock_ip').format(ip)):
            if self.monitor.unblock_ip(ip):
                messagebox.showinfo(tr.get('unblock_ip'), tr.get('success_unblock_ip').format(ip))
                self.update_blocked_lists()
            else:
                messagebox.showerror(tr.get('unblock_ip'), tr.get('error_unblock_ip').format(ip))
    
    def block_selected_app(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        values = self.tree.item(selected[0], 'values')
        pid = values[3]
        
        try:
            process = psutil.Process(int(pid))
            exe_path = process.exe()
            
            if not exe_path:
                messagebox.showerror("Error", tr.get('error_process_info').format("No executable path"))
                return
                
            if messagebox.askyesno(tr.get('block_app'), tr.get('confirm_block_app').format(exe_path)):
                if self.monitor.block_app(exe_path):
                    messagebox.showinfo(tr.get('block_app'), tr.get('success_block_app'))
                    self.update_blocked_lists()
                else:
                    messagebox.showerror(tr.get('block_app'), tr.get('error_block_app'))
        except Exception as e:
            messagebox.showerror("Error", tr.get('error_process_info').format(str(e)))

    def unblock_selected_app(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        values = self.tree.item(selected[0], 'values')
        pid = values[3]
        
        try:
            process = psutil.Process(int(pid))
            exe_path = process.exe()
            
            if not exe_path:
                messagebox.showerror("Error", tr.get('error_process_info').format("No executable path"))
                return
                
            if messagebox.askyesno(tr.get('unblock_app'), tr.get('confirm_unblock_app').format(exe_path)):
                if self.monitor.unblock_app(exe_path):
                    messagebox.showinfo(tr.get('unblock_app'), tr.get('success_unblock_app'))
                    self.update_blocked_lists()
                else:
                    messagebox.showerror(tr.get('unblock_app'), tr.get('error_unblock_app'))
        except Exception as e:
            messagebox.showerror("Error", tr.get('error_process_info').format(str(e)))

    def unblock_selected_app_from_list(self):
        selected = self.blocked_app_listbox.curselection()
        if not selected:
            return
            
        exe_path = self.blocked_app_listbox.get(selected[0])
        if messagebox.askyesno(tr.get('unblock_app'), tr.get('confirm_unblock_app').format(exe_path)):
            if self.monitor.unblock_app(exe_path):
                messagebox.showinfo(tr.get('unblock_app'), tr.get('success_unblock_app'))
                self.update_blocked_lists()
            else:
                messagebox.showerror(tr.get('unblock_app'), tr.get('error_unblock_app'))
    
    def update_blocked_lists(self):
        # Update blocked IPs list
        self.blocked_ip_listbox.delete(0, tk.END)
        for ip in sorted(self.monitor.blocked_ips):
            self.blocked_ip_listbox.insert(tk.END, ip)
        
        # Update blocked apps list
        self.blocked_app_listbox.delete(0, tk.END)
        for app in sorted(self.monitor.blocked_apps):
            self.blocked_app_listbox.insert(tk.END, app)
        
        # Update status in main table
        for item in self.tree.get_children():
            values = list(self.tree.item(item, 'values'))
            if len(values) > 1:
                ip = values[1]
                pid = values[3]
                
                # Check if IP is blocked
                ip_blocked = ip in self.monitor.blocked_ips
                
                # Check if app is blocked
                app_blocked = False
                try:
                    process = psutil.Process(int(pid))
                    exe_path = process.exe()
                    app_blocked = exe_path in self.monitor.blocked_apps
                except:
                    pass
                
                if ip_blocked:
                    values[6] = tr.get('block_status_blocked_ip')
                elif app_blocked:
                    values[6] = tr.get('block_status_blocked_app')
                else:
                    values[6] = tr.get('block_status_unblocked')
                
                self.tree.item(item, values=values)
    
    def start_monitoring(self):
        if self.tray_icon and self.tray_icon._running:
            self.tray_icon.stop()
        try:
            self.update_interval = float(self.interval_entry.get())
            if self.update_interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", tr.get('error_interval'))
            return
        
        self.is_monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(tr.get('status_monitoring'))
        self.monitor_connections()
        
    def stop_monitoring(self):
        self.is_monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set(tr.get('status_stopped'))
        
    def toggle_logging(self):
        if not self.logging_enabled:
            self.setup_log_file()
        else:
            self.close_log_file()
        
    def setup_log_file(self):
        default_filename = f"connection_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=default_filename
        )
        
        if filepath:
            try:
                self.log_file = open(filepath, mode='a', newline='', encoding='utf-8')
                self.log_writer = csv.writer(self.log_file)
                
                if os.path.getsize(filepath) == 0:
                    self.log_writer.writerow([
                        tr.get('col_detection_time'),
                        tr.get('col_remote_ip'), 
                        tr.get('col_port'), 
                        tr.get('col_pid'), 
                        tr.get('col_process_name'),
                        "Executable Path",
                        tr.get('col_block_status')
                    ])
                
                self.logging_enabled = True
                self.log_btn.config(text=tr.get('disable_logging'))
                messagebox.showinfo("Logging", tr.get('logging_enabled').format(filepath))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open log file: {str(e)}")
        
    def close_log_file(self):
        if self.log_file:
            try:
                self.log_file.close()
            except:
                pass
        self.logging_enabled = False
        self.log_btn.config(text=tr.get('enable_logging'))
        messagebox.showinfo("Logging", tr.get('logging_disabled'))
        
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set(tr.get('status_cleared'))
        
    def log_connection(self, detection_time, remote_ip, port, pid, process_name, exe_path):
        if self.logging_enabled and self.log_file:
            try:
                if remote_ip in self.monitor.blocked_ips:
                    block_status = tr.get('block_status_blocked_ip')
                elif exe_path in self.monitor.blocked_apps:
                    block_status = tr.get('block_status_blocked_app')
                else:
                    block_status = tr.get('block_status_unblocked')
                
                self.log_writer.writerow([
                    detection_time,
                    remote_ip,
                    port,
                    pid,
                    process_name,
                    exe_path,
                    block_status
                ])
                self.log_file.flush()
                return tr.get('log_status_saved')
            except Exception as e:
                return tr.get('log_status_error').format(str(e))
        return tr.get('log_status_not_saved')
        
    def monitor_connections(self):
        if not self.is_monitoring:
            return
            
        current_conn = self.monitor.get_current_connections()
        new_conn = current_conn - self.monitor.known_connections
        
        if new_conn:
            detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for conn in new_conn:
                remote_ip, remote_port, pid, process_name, exe_path = conn
                
                if remote_ip in self.monitor.blocked_ips:
                    block_status = tr.get('block_status_blocked_ip')
                elif exe_path in self.monitor.blocked_apps:
                    block_status = tr.get('block_status_blocked_app')
                else:
                    block_status = tr.get('block_status_unblocked')
                
                log_status = self.log_connection(detection_time, remote_ip, remote_port, pid, process_name, exe_path)
                
                self.tree.insert("", tk.END, values=(
                    detection_time,
                    remote_ip,
                    remote_port,
                    pid,
                    process_name,
                    log_status,
                    block_status
                ))
            
            self.monitor.known_connections.update(new_conn)
            last_update = datetime.now().strftime('%H:%M:%S')
            if tr.current_lang == 'EN':
                self.status_var.set(f"Found {len(new_conn)} new connections | Last update: {last_update}")
            else:
                self.status_var.set(f"Znaleziono {len(new_conn)} nowych połączeń | Ostatnia aktualizacja: {last_update}")
        else:
            last_update = datetime.now().strftime('%H:%M:%S')
            if tr.current_lang == 'EN':
                self.status_var.set(f"No new connections | Last update: {last_update}")
            else:
                self.status_var.set(f"Brak nowych połączeń | Ostatnia aktualizacja: {last_update}")
        
        self.root.after(int(self.update_interval * 1000), self.monitor_connections)

def main():
    root = tk.Tk()
    
    if platform.system() == 'Windows':
        try:
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                sys.exit()
            else:
                print("Running with administrator privileges")
        except Exception as e:
            print(f"Error trying to run as administrator: {e}")
            messagebox.showerror("Error", tr.get('error_admin'))
            return
    
    if sys.platform == 'win32':
        myappid = 'network.monitor.app.1.0'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    
    app = NetworkMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    try:
        import pyperclip
    except ImportError:
        print("Installing required pyperclip library...")
        import subprocess
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pyperclip"],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        import pyperclip
    
    main()