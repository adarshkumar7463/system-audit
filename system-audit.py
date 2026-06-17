import sys
import platform
from datetime import datetime   #netsh wlan show drivers
import getpass
import os
import subprocess
import winreg
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox,
    QPushButton, QDialog, QFormLayout, QLineEdit, QStackedLayout,
    QListWidget, QListWidgetItem, QTextEdit, QComboBox, QFileDialog, QMessageBox, QInputDialog
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QLabel, QHBoxLayout
from fpdf import FPDF

import ctypes
import winreg




# ------ Step 1: Create Login Dialog ------
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
# 1. ------------------- Login Dialog -------------------





def toggle_hotspot(enable=True):
    try:
        if enable:
            subprocess.run([
                "netsh", "wlan", "set", "hostednetwork",
                "mode=allow", "ssid=MyHotspot", "key=12345678"
            ], check=True)
            subprocess.run(["netsh", "wlan", "start", "hostednetwork"], check=True)
        else:
            subprocess.run(["netsh", "wlan", "stop", "hostednetwork"], check=True)

        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Hotspot", f"Hotspot has been {status}.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Hotspot {status}.")

    except subprocess.CalledProcessError as e:
        QMessageBox.critical(None, "Hotspot Error", f"Failed to toggle Hotspot: {e}")


# Helper: Run PowerShell commands
def run_powershell(command):
    powershell_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    result = subprocess.run([powershell_path, "-Command", command], capture_output=True, text=True)
    return result.returncode == 0

# Helper: Toggle Windows registry values
import winreg

def toggle_registry_value(path, name, value_type, value):
    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            winreg.SetValueEx(key, name, 0, value_type, value)
        return True
    except Exception as e:
        print(f"[✗] Registry error: {e}")
        return False


def toggle_current_user_registry_value(path, name, value_type, value):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, name, 0, value_type, value)
        return True
    except Exception as e:
        print(f"User Registry error: {e}")
        return False
    
def set_display_timeout(enable=True):
    try:
        minutes = 5 if enable else 0
        subprocess.run(["powercfg", "/change", "monitor-timeout-ac", str(minutes)], check=True)
        subprocess.run(["powercfg", "/change", "monitor-timeout-dc", str(minutes)], check=True)
        return True
    except Exception as e:
        print(f"[✗] Failed to set display timeout: {e}")
        return False
def set_power_saving_mode(enable=True):
    try:
        scheme = "a1841308-3541-4fab-bc81-f71556f20b4a" if enable else "381b4222-f694-41f0-9685-ff5bb260df2e"
        subprocess.run(["powercfg", "/setactive", scheme], check=True)
        return True
    except Exception as e:
        print(f"[✗] Failed to set power scheme: {e}")
        return False



class PasswordDialog(QDialog):
    def __init__(self, title):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(300, 150)
        layout = QFormLayout(self)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("New Password:", self.password_input)
        update_btn = QPushButton("Update")
        update_btn.clicked.connect(self.accept)
        layout.addRow(update_btn)

    def get_password(self):
        return self.password_input.text()
    
def simulate_bios_password(enable):
    status = "ENABLED" if enable else "DISABLED"
    print(f"[SIMULATION] BIOS password has been {status}.")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    StatusRow.activity_log.append(f"{timestamp}: BIOS password {status}.")
    QMessageBox.information(None, "BIOS Password", f"BIOS password {status}.")


class StatusRow(QWidget):
    activity_log = []
    status_stats = {}

    def __init__(self, label_text, is_password=False):
        super().__init__()
        self.status = False
        self.label_text = label_text
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)

        self.label = QLabel(label_text)
        self.label.setFont(QFont("Segoe UI", 11))
        layout.addWidget(self.label)

        self.status_label = QLabel("\ud83d\udd34 Inactive")
        self.status_label.setStyleSheet("font-weight: bold; color: red;")
        layout.addWidget(self.status_label)

        self.toggle_btn = QPushButton("\ud83d\udfe2")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setStyleSheet(
            "QPushButton { border-radius: 10px; padding: 5px; font-weight: bold; background-color: lightgray; }"
            "QPushButton:checked { background-color: green; color: white; }")
        self.toggle_btn.clicked.connect(self.toggle_status)
        layout.addWidget(self.toggle_btn)

        if is_password:
            self.update_btn = QPushButton("Update Password")
            self.update_btn.setStyleSheet("background-color: #0078d7; color: white;")
            self.update_btn.clicked.connect(self.update_password)
            layout.addWidget(self.update_btn)

        self.setLayout(layout)

    def toggle_status(self):
        self.status = not self.status
        state = "\ud83d\udfe2 Active" if self.status else "\ud83d\udd34 Inactive"
        color = "green" if self.status else "red"
        self.status_label.setText(state)
        self.status_label.setStyleSheet(f"font-weight: bold; color: {color};")

        if "BIOS" in self.label_text or self.label_text in ["Boot Order Lock", "Secure Boot"]:
            self.simulate_bios_setting(self.label_text, self.status)

        if self.label_text in ["WiFi", "Bluetooth", "Hotspot"]:
            self.simulate_wireless_setting(self.label_text, self.status)

        
        label_clean = self.label_text.strip()
        label_clean = self.label_text.strip()
        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
            except Exception as e:
                QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if label_clean == "Ctrl+Alt+Del":
            SECURITY_POLICY_ACTIONS["Ctrl+Alt+Del"](self.status)

        
        elif label_clean == "Restart":
            handle_restart()
        elif label_clean == "Shut Down":
            handle_shutdown()
        elif label_clean == "Refresh":
            handle_refresh()

        entry = f"{timestamp}: {self.label_text} set to {'Active' if self.status else 'Inactive'}"
        StatusRow.activity_log.append(entry)
        StatusRow.status_stats[self.label_text] = StatusRow.status_stats.get(self.label_text, 0) + int(self.status)

        label_clean = self.label_text.strip()

        if label_clean == "USB Lock":
            QMessageBox.information(self, "USB Lock", "Changes will take effect after a system restart.")


# NEW: Custom real-time logging
        if label_clean == "Login/Logout Logs":    
            try:
                SECURITY_POLICY_ACTIONS["Login/Logout Logs"](self.status)
                QMessageBox.information(self, "Audit Log Toggle", f"Login/Logout log auditing {'enabled' if self.status else 'disabled'}.")
            except Exception as e:
                QMessageBox.critical(self, "Log Toggle Error", f"Failed to toggle log auditing: {e}")

        if label_clean == "Display Timeout":
            result = SECURITY_POLICY_ACTIONS["Display Timeout"](self.status)
        if result:
                QMessageBox.information(self, "Display Timeout", f"Display Timeout has been {'enabled' if self.status else 'disabled'}.")
        else:
                QMessageBox.critical(self, "Error", "Failed to change Display Timeout.")

        if label_clean == "Power Saving Mode":
            result = SECURITY_POLICY_ACTIONS["Power Saving Mode"](self.status)
        if result:
            QMessageBox.information(self, "Power Scheme", f"Power Saving Mode has been {'enabled' if self.status else 'disabled'}.")
        else:
            QMessageBox.critical(self, "Error", "Failed to change power mode.")



        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
                QMessageBox.information(self, "Policy Applied", f"{label_clean} set to {'Enabled' if self.status else 'Disabled'}.")
            except Exception as e:
                QMessageBox.critical(self, "Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
                QMessageBox.information(self, "Policy Applied", f"{label_clean} set to {'Enabled' if self.status else 'Disabled'}.")
            except Exception as e:
                QMessageBox.critical(self, "Policy Error", f"Failed to apply policy '{label_clean}': {e}")



    def update_password(self):
        dialog = PasswordDialog("Update Password")
        if dialog.exec_() == QDialog.Accepted:
            new_password = dialog.get_password()
            if new_password:
                self.status_label.setText("\ud83d\udfe2 Password Updated")
                self.status_label.setStyleSheet("font-weight: bold; color: darkgreen;")
        
        label_clean = self.label_text.strip()
        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
            except Exception as e:
                QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Password updated for {self.label_text}")

    def simulate_bios_setting(self, setting, enabled):
        print(f"[SIMULATION] BIOS Setting '{setting}' has been {'ENABLED' if enabled else 'DISABLED'}.")





# ========== Wireless Adapter Control Functions (GUI-based only) ==========

def toggle_bluetooth(enable=True):
    try:
        if not is_admin():
            QMessageBox.critical(None, "Permissions Error", "Bluetooth toggle requires administrator privileges.")
            return

        if enable:
            script = (
                "Get-PnpDevice -Class Bluetooth | "
                "Where-Object { $_.Status -ne 'OK' } | "
                "ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )
        else:
            script = (
                "Get-PnpDevice -Class Bluetooth | "
                "Where-Object { $_.Status -eq 'OK' } | "
                "ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )

        subprocess.run(["powershell", "-Command", script], check=True)
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Bluetooth", f"Bluetooth has been {status}.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Bluetooth {status}.")

    except subprocess.CalledProcessError as e:
        print(f"[✗] Failed to toggle Bluetooth. Error: {e}")
        QMessageBox.critical(None, "Bluetooth Error", f"Failed to toggle Bluetooth: {e}")

def toggle_inactive_user_removal(enable=True):
    try:
        if not enable:
            QMessageBox.information(None, "Inactive User Removal", "Toggle OFF: No action taken.")
            return True

        days_threshold = 30
        script = f"""
        $threshold = (Get-Date).AddDays(-{days_threshold})
        $users = Get-LocalUser | Where-Object {{
            $_.Enabled -eq $true -and
            $_.Name -ne "Administrator" -and
            $_.Name -ne "Guest" -and
            $_.LastLogon -ne $null -and
            $_.LastLogon -lt $threshold
        }}
        $removed = @()
        foreach ($user in $users) {{
            Remove-LocalUser -Name $user.Name
            $removed += $user.Name
        }}
        if ($removed.Count -eq 0) {{
            "No inactive users found."
        }} else {{
            "Removed users: " + ($removed -join ", ")
        }}
        """

        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr.strip())

        output = result.stdout.strip() or "No inactive users found."
        QMessageBox.information(None, "Inactive User Removal", output)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Inactive user removal result: {output}")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Inactive User Error", f"Failed to remove inactive users: {e}")
        return False


def toggle_signature_update(enable=True):
    try:
        if enable:
            # Run the update command
            command = "Update-MpSignature"
            result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)

            if result.returncode != 0:
                raise Exception(result.stderr.strip())

            QMessageBox.information(None, "Signature Update", "Virus signatures have been updated successfully.")
            status = "updated"
        else:
            QMessageBox.information(None, "Signature Update", "Signature update skipped.")
            status = "skipped"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Signature update {status}.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Signature Update Error", f"Failed to update signatures: {e}")
        return False

def toggle_disk_encryption(enable=True):
    try:
        drive = "C:"

        if enable:
            cmd = f'Resume-BitLocker -MountPoint "{drive}"'
        else:
            cmd = f'Suspend-BitLocker -MountPoint "{drive}" -RebootCount 0'

        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr.strip())

        status = "resumed (active)" if enable else "suspended (inactive)"
        QMessageBox.information(None, "Disk Encryption", f"BitLocker has been {status} on {drive}.")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: BitLocker {status} on {drive}.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Disk Encryption Error", f"Failed: {e}")
        return False

def toggle_backup_schedule(enable=True):
    try:
        task_name = "CyberAuditDataBackup"
        script_path = r"C:\CyberAudit\backup_script.ps1"

        if enable:
            # Create task to run daily at 6 PM
            cmd = (
                f'schtasks /Create /TN "{task_name}" /TR "powershell -ExecutionPolicy Bypass -File \\"{script_path}\\"" '
                '/SC DAILY /ST 18:00 /RL HIGHEST /F'
            )
        else:
            # Delete the task
            cmd = f'schtasks /Delete /TN "{task_name}" /F'

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr.strip())

        status = "scheduled" if enable else "canceled"
        QMessageBox.information(None, "Backup Schedule", f"Backup task has been {status} successfully.")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Data backup schedule {status}.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Backup Schedule Error", f"Failed to update schedule: {e}")
        return False


def toggle_admin_rights(enable=True):
    try:
        username = getpass.getuser()  # get current username

        if enable:
            cmd = f'net localgroup Administrators "{username}" /add'
        else:
            cmd = f'net localgroup Administrators "{username}" /delete'

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr.strip())

        status = "granted" if enable else "revoked"
        QMessageBox.information(None, "Admin Rights", f"Admin rights have been {status} for user: {username}")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Admin rights {status} for user {username}.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Admin Rights Error", f"Failed to change admin rights: {e}")
        return False


def toggle_antivirus_check(enable=True):
    try:
        if enable:
            # Check if antivirus is installed using WMI
            command = (
                "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntivirusProduct | "
                "Select-Object -Property displayName,productState"
            )
            result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)

            if result.returncode != 0 or not result.stdout.strip():
                QMessageBox.critical(None, "Antivirus Status", "No antivirus detected or query failed.")
                return False

            QMessageBox.information(None, "Antivirus Status", f"Antivirus Detected:\n{result.stdout.strip()}")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            StatusRow.activity_log.append(f"{timestamp}: Antivirus check performed. Detected:\n{result.stdout.strip()}")
        else:
            QMessageBox.information(None, "Antivirus Check", "Antivirus check is disabled (no status will be shown).")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            StatusRow.activity_log.append(f"{timestamp}: Antivirus check disabled.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Antivirus Check Failed", f"Error: {e}")
        return False
    
def toggle_auto_scan(enable=True):
    try:
        # PowerShell command to enable/disable real-time protection
        command = f"Set-MpPreference -DisableRealtimeMonitoring:{'false' if enable else 'true'}"

        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr.strip())

        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Auto Scan", f"Auto Scan (Real-time Protection) has been {status}.")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Auto Scan {status}.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Auto Scan Error", f"Failed to toggle Auto Scan: {e}")
        return False
    
def toggle_biometric(self, state):
    if state == Qt.Checked:
        QMessageBox.information(self, "Biometric Access", "✅ Biometric Access Enabled")
        self.biometric_enabled = True  # or any flag you use
    else:
        QMessageBox.warning(self, "Biometric Access", "❌ Biometric Access Disabled")
        self.biometric_enabled = False
    
def toggle_firewall(enable=True):
    try:
        cmd = f'netsh advfirewall set allprofiles state {"on" if enable else "off"}'

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip())

        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Firewall", f"Windows Firewall has been {status}.")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Windows Firewall {status}.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Firewall Error", f"Failed to update firewall status: {e}")
        return False



def toggle_browser_hardening(enable=True):
    try:
        import winreg

        # Correct policy keys for Chrome and Edge
        chrome_path = r"SOFTWARE\Policies\Google\Chrome"
        edge_path = r"SOFTWARE\Policies\Microsoft\Edge"

        # Correct and working registry policy values
        policies = {
            "IncognitoModeAvailability": 1 if enable else 0,  # 1 = disable Incognito
            "DefaultJavaScriptSetting": 2 if enable else 1,   # 2 = block JS, 1 = allow
            "DefaultPopupsSetting": 2 if enable else 1, 
                  
            "https://www.instagram.com/accounts/login/?hl=en" : 1 if enable else 0,           # 2 = block, 1 = allow
        }

        # Apply settings to both Chrome and Edge
        for path in [chrome_path, edge_path]:
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
                for name, value in policies.items():
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            except Exception as e:
                print(f"[✗] Failed to write registry for {path}: {e}")
                return False

        QMessageBox.information(None, "Browser Hardening",
            "Browser hardening has been applied.\nPlease restart your browser.\nTo verify, go to: chrome://policy")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Browser Hardening {'enabled' if enable else 'disabled'}.")
        return True

    except Exception as e:
        QMessageBox.critical(None, "Hardening Error", f"Browser Hardening Failed: {e}")
        return False

def toggle_popup_blocker(enable=True):
    try:
        import winreg

        # Registry paths
        chrome_path = r"SOFTWARE\Policies\Google\Chrome"
        edge_path = r"SOFTWARE\Policies\Microsoft\Edge"

        value = 2 if enable else 1  # 2 = block pop-ups, 1 = allow

        # Set registry key for both browsers
        for browser_path in [chrome_path, edge_path]:
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, browser_path)
                winreg.SetValueEx(key, "DefaultPopupsSetting", 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            except Exception as e:
                print(f"[✗] Registry error for {browser_path}: {e}")
                return False

        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Pop-up Blocker",
            f"Pop-up blocker has been {status}.\nRestart Chrome, then visit chrome://policy to verify.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Pop-up Blocker {status}.")
        return True

    except Exception as e:
        QMessageBox.critical(None, "Pop-up Blocker Error", f"Failed: {e}")
        return False

def toggle_https_enforced(enable=True):
    try:
        import winreg

        chrome_path = r"SOFTWARE\Policies\Google\Chrome"
        edge_path = r"SOFTWARE\Policies\Microsoft\Edge"

        value = 1 if enable else 0  # 1 = enforce HTTPS

        for browser_path in [chrome_path, edge_path]:
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, browser_path)
                winreg.SetValueEx(key, "ForceHTTPS", 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            except Exception as e:
                print(f"[✗] Failed to write to {browser_path}: {e}")
                return False

        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "HTTPS Enforced",
            f"HTTPS Enforcement has been {status}.\nRestart Chrome or Edge and visit chrome://policy to verify.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: HTTPS Enforced {status}.")
        return True

    except Exception as e:
        QMessageBox.critical(None, "HTTPS Enforcement Error", f"Failed to apply setting: {e}")
        return False


def toggle_folder_access_control(enable=True):
    folder_path = r"C:\SecureFolder"

    # Make sure the folder exists
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path)
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Failed to create folder: {e}")
            return False

    try:
        if enable:
            # Grant full access to Everyone
            cmd = f'icacls "{folder_path}" /grant Everyone:(F) /T /C'
        else:
            # Remove permissions for Everyone (deny access)
            cmd = f'icacls "{folder_path}" /deny Everyone:(F) /T /C'

        subprocess.run(cmd, shell=True, check=True)
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Folder Access", f"Access to {folder_path} has been {status}.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: File/Folder access {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Folder Access Error", f"Failed to toggle folder access: {e}")
        return False


def toggle_cd_dvd_access(enable=True):
    try:
        if not is_admin():
            QMessageBox.critical(None, "Permissions Error", "CD/DVD access toggle requires administrator privileges.")
            return

        if enable:
            script = (
                "Get-PnpDevice | Where-Object { $_.Class -eq 'CDROM' -and $_.Status -ne 'OK' } | "
                "ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )
        else:
            script = (
                "Get-PnpDevice | Where-Object { $_.Class -eq 'CDROM' -and $_.Status -eq 'OK' } | "
                "ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )

        subprocess.run(["powershell", "-Command", script], check=True)
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "CD/DVD Access", f"CD/DVD drives have been {status}.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: CD/DVD Access {status}.")

    except subprocess.CalledProcessError as e:
        print(f"[✗] Failed to toggle CD/DVD. Error: {e}")
        QMessageBox.critical(None, "CD/DVD Error", f"Failed to toggle CD/DVD access: {e}")

def toggle_disk_encryption(enable=True):
    try:
        drive = "C:"
        if enable:
            # Check if already encrypted
            check_cmd = f'Get-BitLockerVolume -MountPoint "{drive}" | Select-Object VolumeStatus'
            result = subprocess.run(["powershell", "-Command", check_cmd], capture_output=True, text=True)

            if "FullyEncrypted" in result.stdout:
                QMessageBox.information(None, "Disk Encryption", "Disk is already encrypted.")
                return True

            # Attempt to enable BitLocker
            cmd = (
                f'Enable-BitLocker -MountPoint "{drive}" '
                '-EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmProtector'
            )
        else:
            # Attempt to disable BitLocker
            cmd = f'Disable-BitLocker -MountPoint "{drive}"'

        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr.strip())

        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Disk Encryption", f"BitLocker has been {status} on {drive}.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Disk encryption {status} on {drive}.")

        return True

    except Exception as e:
        QMessageBox.critical(None, "Disk Encryption Error", f"Failed: {e}")
        return False



def toggle_usb_adapter(enable=True):
    try:
        if not is_admin():
            QMessageBox.critical(None, "Permissions Error", "USB toggle requires administrator privileges.")
            return

        if enable:
            # Enable all USB devices
            script = (
                "Get-PnpDevice | Where-Object { $_.Class -eq 'USB' -and $_.Status -ne 'OK' } | "
                "ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )
        else:
            # Disable all USB devices
            script = (
                "Get-PnpDevice | Where-Object { $_.Class -eq 'USB' -and $_.Status -eq 'OK' } | "
                "ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )

        subprocess.run(["powershell", "-Command", script], check=True)
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "USB Adapter", f"USB ports have been {status}.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: USB Adapter {status}.")

    except subprocess.CalledProcessError as e:
        print(f"[✗] Failed to toggle USB. Error: {e}")
        QMessageBox.critical(None, "USB Toggle Error", f"Failed to toggle USB: {e}")


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def set_adapter_state(adapter_name, enable=True):
    state = 'enable' if enable else 'disable'
    cmd = f'netsh interface set interface "{adapter_name}" {state}'
    try:
        subprocess.check_call(cmd, shell=True)
        message = f"Adapter '{adapter_name}' has been {state}d."
        print(f"[✓] {message}")
        QMessageBox.information(None, "Success", message)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Adapter '{adapter_name}' {state}d successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[✗] Failed to {state} adapter '{adapter_name}'. Error: {e}")
        QMessageBox.critical(None, "Adapter Error", f"Failed to {state} adapter: {e}")
        return
class StatusRow(QWidget):
    activity_log = []
    status_stats = {}

    def __init__(self, label_text, is_password=False):
        super().__init__()
        self.status = False
        self.label_text = label_text
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)

        self.label = QLabel(label_text)
        self.label.setFont(QFont("Segoe UI", 11))
        layout.addWidget(self.label)

        self.status_label = QLabel("🔴 Inactive")
        self.status_label.setStyleSheet("font-weight: bold; color: red;")
        layout.addWidget(self.status_label)

        self.toggle_btn = QPushButton("🟢")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setStyleSheet(
            "QPushButton { border-radius: 10px; padding: 5px; font-weight: bold; background-color: lightgray; }"
            "QPushButton:checked { background-color: green; color: white; }")
        self.toggle_btn.clicked.connect(self.toggle_status)
        layout.addWidget(self.toggle_btn)

        if is_password:
            self.update_btn = QPushButton("Update Password")
            self.update_btn.setStyleSheet("background-color: #0078d7; color: white;")
            self.update_btn.clicked.connect(self.update_password)
            layout.addWidget(self.update_btn)

        self.setLayout(layout)

    def toggle_status(self):
        self.status = not self.status
        state = "🟢 Active" if self.status else "🔴 Inactive"
        color = "green" if self.status else "red"
        self.status_label.setText(state)
        self.status_label.setStyleSheet(f"font-weight: bold; color: {color};")

        if "BIOS" in self.label_text or self.label_text in ["Boot Order Lock", "Secure Boot"]:
            self.simulate_bios_setting(self.label_text, self.status)

        label_clean = self.label_text.strip()
        if label_clean == "WiFi":
            adapter_name, ok = QInputDialog.getText(self, "Adapter Name", "Enter the adapter name for WiFi:")
            if ok and adapter_name:
                set_adapter_state(adapter_name, enable=self.status)

        elif label_clean == "Bluetooth":
            toggle_bluetooth(enable=self.status)

        elif label_clean == "Hotspot":
            try:
                if self.status:
                    subprocess.check_call("netsh wlan start hostednetwork", shell=True)
                    QMessageBox.information(self, "Hotspot", "Hotspot started successfully.")
                else:
                    subprocess.check_call("netsh wlan stop hostednetwork", shell=True)
                    QMessageBox.information(self, "Hotspot", "Hotspot stopped.")
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, "Hotspot Error", f"Failed to toggle hotspot: {e}")

        
        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
            except Exception as e:
                QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if label_clean == "Ctrl+Alt+Del":
            SECURITY_POLICY_ACTIONS["Ctrl+Alt+Del"](self.status)

        
        elif label_clean == "Restart":
            handle_restart()
        elif label_clean == "Shut Down":
            handle_shutdown()
        elif label_clean == "Refresh":
            handle_refresh()

        entry = f"{timestamp}: {self.label_text} set to {'Active' if self.status else 'Inactive'}"
        StatusRow.activity_log.append(entry)
        StatusRow.status_stats[self.label_text] = StatusRow.status_stats.get(self.label_text, 0) + int(self.status)

    def update_password(self):
        dialog = PasswordDialog("Update Password")
        if dialog.exec_() == QDialog.Accepted:
            new_password = dialog.get_password()
            if new_password:
                self.status_label.setText("🟢 Password Updated")
                self.status_label.setStyleSheet("font-weight: bold; color: darkgreen;")
        
        label_clean = self.label_text.strip()
        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
            except Exception as e:
                QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Password updated for {self.label_text}")

    def simulate_bios_setting(self, setting, enabled):
        print(f"[SIMULATION] BIOS Setting '{setting}' has been {'ENABLED' if enabled else 'DISABLED'}.")

        # Wireless adapter control
        label_clean = self.label_text.strip()
        if label_clean == "WiFi":
            adapter_name, ok = QInputDialog.getText(self, "Adapter Name", "Enter the adapter name for WiFi:")
            if ok and adapter_name:
                set_adapter_state(adapter_name, enable=self.status)

        elif label_clean == "Bluetooth":
            toggle_bluetooth(enable=self.status)

        elif label_clean == "Hotspot":
            try:
                if self.status:
                    subprocess.check_call("netsh wlan start hostednetwork", shell=True)
                    QMessageBox.information(self, "Hotspot", "Hotspot started successfully.")
                else:
                    subprocess.check_call("netsh wlan stop hostednetwork", shell=True)
                    QMessageBox.information(self, "Hotspot", "Hotspot stopped.")
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, "Hotspot Error", f"Failed to toggle hotspot: {e}")

        
        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
            except Exception as e:
                QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if label_clean == "Ctrl+Alt+Del":
            SECURITY_POLICY_ACTIONS["Ctrl+Alt+Del"](self.status)

        
        elif label_clean == "Restart":
            handle_restart()
        elif label_clean == "Shut Down":
            handle_shutdown()
        elif label_clean == "Refresh":
            handle_refresh()

        entry = f"{timestamp}: {self.label_text} set to {'Active' if self.status else 'Inactive'}"
        StatusRow.activity_log.append(entry)
        StatusRow.status_stats[self.label_text] = StatusRow.status_stats.get(self.label_text, 0) + int(self.status)

def update_password(self):
    dialog = PasswordDialog("Update Password")
    if dialog.exec_() == QDialog.Accepted:
        new_password = dialog.get_password()
        if new_password:
            self.status_label.setText("🟢 Password Updated")
            self.status_label.setStyleSheet("font-weight: bold; color: darkgreen;")
        
        label_clean = self.label_text.strip()
        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
            except Exception as e:
                QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Password updated for {self.label_text}")

def simulate_bios_setting(self, setting, enabled):
    print(f"[SIMULATION] BIOS Setting '{setting}' has been {'ENABLED' if enabled else 'DISABLED'}.")

    if setting == "Bluetooth":
        try:
            if not is_admin():
                QMessageBox.critical(None, "Permissions Error", "Bluetooth toggle requires administrator privileges.")
                return

            if enabled:
                script = (
                    "Get-PnpDevice -Class Bluetooth | "
                    "Where-Object { $_.Status -ne 'OK' } | "
                    "ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
                )
            else:
                script = (
                    "Get-PnpDevice -Class Bluetooth | "
                    "Where-Object { $_.Status -eq 'OK' } | "
                    "ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
                )

            subprocess.run(["powershell", "-Command", script], check=True)
            status = "enabled" if enabled else "disabled"
            QMessageBox.information(None, "Bluetooth", f"Bluetooth has been {status}.")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            StatusRow.activity_log.append(f"{timestamp}: Bluetooth {status}.")

            # Optional: Use SECURITY_POLICY_ACTIONS if needed
            label_clean = "Bluetooth"
            if label_clean in SECURITY_POLICY_ACTIONS:
                SECURITY_POLICY_ACTIONS[label_clean](enabled)

        except Exception as e:
            QMessageBox.critical(None, "Bluetooth Error", f"Failed to toggle Bluetooth: {e}")

SECURITY_POLICY_ACTIONS = {
    "Audit Policy": lambda enable: run_powershell(
        r'C:\\Windows\\System32\\auditpol.exe /set /category:"Logon/Logoff" '
        f'/success:{"enable" if enable else "disable"} /failure:{"enable" if enable else "disable"}'
    ),
    "Guest Account": lambda enable: run_powershell(
        r'C:\\Windows\\System32\\net.exe user guest /active:' + ('yes' if enable else 'no')
        ),

    "Access Permissions": lambda enable: toggle_folder_access_control(enable),
    "Browser Hardening": lambda enable: toggle_browser_hardening(enable),
    "Pop-up Blocker": lambda enable: toggle_popup_blocker(enable),
    "HTTPS Enforced": lambda enable: toggle_https_enforced(enable),
    "Antivirus Installed": lambda enable: toggle_antivirus_check(enable),
    "Auto Scan Enabled": lambda enable: toggle_auto_scan(enable),
    "Signature Updates": lambda enable: toggle_signature_update(enable),
    "Admin Rights Control": lambda enable: toggle_admin_rights(enable),
    "Inactive User Removal": lambda enable: toggle_inactive_user_removal(enable),
    "Disk Encryption": lambda enable: toggle_disk_encryption(enable),
    "Data Backup Schedule": lambda enable: toggle_backup_schedule(enable),
    "Firewall Enabled": lambda enable: toggle_firewall(enable),
    "Biometric Access": lambda enable: toggle_registry_value(
        r"SOFTWARE\\Policies\\Microsoft\\Biometrics",
        "Enabled",
        winreg.REG_DWORD,
        1 if enable else 0
    ),







   "USB Lock": lambda enable: toggle_registry_value(
    r"SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
    "Start",
    winreg.REG_DWORD,
    3 if enable else 4  # 3 = Enabled, 4 = Disabled
),

"USB Lock": lambda enable: toggle_usb_adapter(enable),

"CD/DVD Access": lambda enable: toggle_cd_dvd_access(enable),

"Display Timeout": lambda enable: set_display_timeout(enable),



    
    
    "Ctrl+Alt+Del": lambda enable: toggle_registry_value(
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "DisableCAD",
        winreg.REG_DWORD,
        0 if enable else 1
    ),
    "Display Last User": lambda enable: toggle_registry_value(
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "DontDisplayLastUserName",
        winreg.REG_DWORD,
        0 if enable else 1
    ),
    "Clear Virtual Memory": lambda enable: toggle_registry_value(
        r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        "ClearPageFileAtShutdown",
        winreg.REG_DWORD,
        1 if enable else 0
    ),

    "Login Timeout": lambda enable: toggle_registry_value(
    r"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
    "MaxIdleTime",
    winreg.REG_DWORD,
    300000 if enable else 0  # 5 min vs no timeout
),

"Biometric Access": lambda enable: toggle_registry_value(
    r"SOFTWARE\\Policies\\Microsoft\\Biometrics",
    "Enabled",
    winreg.REG_DWORD,
    1 if enable else 0
),




       "Login/Logout Logs": lambda enable: run_powershell(
        r'auditpol /set /category:"Logon/Logoff" '
        f'/success:{"enable" if enable else "disable"} /failure:{"enable" if enable else "disable"}'
    ),
    "Security Log Retention": lambda enable: run_powershell(
        f'wevtutil sl Security /rt:{"true" if enable else "false"}'
    ),
    "Log File Encryption": lambda enable: run_powershell(
        f'cipher /{"E" if enable else "D"} /A /S:"C:\\AuditLogs"'
    ),

    "2FA Enabled": lambda enable: toggle_registry_value(
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "scforceoption",
    winreg.REG_DWORD,
    1 if enable else 0
),

"Auto Screen Lock": lambda enable: (
    toggle_current_user_registry_value(
        r"Control Panel\\Desktop", "ScreenSaverIsSecure", winreg.REG_SZ, "1" if enable else "0"
    ) and
    toggle_current_user_registry_value(
        r"Control Panel\\Desktop", "ScreenSaveTimeOut", winreg.REG_SZ, "300" if enable else "0"
    )
),
    "Display Timeout": lambda enable: set_display_timeout(enable),
    "Power Saving Mode": lambda enable: set_power_saving_mode(enable),
    "BIOS Password": lambda enable: simulate_bios_password(enable),
    "Boot Order Lock": lambda enable: simulate_bios_setting("Boot Order Lock", enable),
    "Secure Boot": lambda enable: simulate_bios_setting("Secure Boot", enable),



}




def update_password(self):
        dialog = PasswordDialog("Update Password")
        if dialog.exec_() == QDialog.Accepted:
            new_password = dialog.get_password()
            if new_password:
                self.status_label.setText("🟢 Password Updated")
                self.status_label.setStyleSheet("font-weight: bold; color: darkgreen;")
        
        label_clean = self.label_text.strip()
        if label_clean in SECURITY_POLICY_ACTIONS:
            try:
                SECURITY_POLICY_ACTIONS[label_clean](self.status)
            except Exception as e:
                QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: Password updated for {self.label_text}")

def simulate_bios_setting(self, setting, enabled):
        print(f"[SIMULATION] BIOS Setting '{setting}' has been {'ENABLED' if enabled else 'DISABLED'}.")



class SectionBox(QGroupBox):
    def __init__(self, title, items, is_password=False):
        super().__init__(title)
        self.setStyleSheet("QGroupBox { font-size: 15px; font-weight: bold; margin-top: 10px; }")
        layout = QVBoxLayout()
        for item in items:
            layout.addWidget(StatusRow(item, is_password and "password" in item.lower()))
        self.setLayout(layout)

def get_system_info():
    return f"System: {platform.system()} | Node: {platform.node()} | Release: {platform.release()} | Version: {platform.version()} | Machine: {platform.machine()} | Processor: {platform.processor()}"

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("External System Security Audit - SLOG Solutions Pvt. Ltd.")
        self.setMinimumSize(1100, 900)
        main_layout = QVBoxLayout(self)

        title_label = QLabel("\ud83d\udd10 External System Security Audit   SLOG Solutions Pvt. Ltd")
        title_label.setFont(QFont("Arial", 20, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: navy; padding: 10px;")

        self.system_info_label = QLabel(get_system_info())
        self.system_info_label.setAlignment(Qt.AlignCenter)
        self.system_info_label.setStyleSheet("color: black; font-size: 11pt; padding-bottom: 10px;")

        main_layout.addWidget(title_label)
        main_layout.addWidget(self.system_info_label)

        content_layout = QHBoxLayout()

        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(280)
        self.sidebar.setStyleSheet("""
            QListWidget {
                background-color: #2d2d30;
                color: white;
                font-size: 14px;
            }
            QListWidget::item:selected {
                background-color: #0078d7;
                color: white;
            }
        """)

        self.sections = {
            "\ud83d\udd10 BIOS Hardening": ["BIOS Password", "Boot Order Lock", "Secure Boot"],
            "💻 OS Security": ["OS Patch Update", "Firewall Enabled", "Account Lockout", "Password Policy"],
            "🔒 Security Policy": ["Guest Account", "Audit Policy", "Ctrl+Alt+Del","Display Last User","Clear Virtual Memory"],
            "📡 Network Security": ["Disable Unused Ports", "Configure VLANs", "Firewall Rules", "MAC Filtering"],
            "🗔️ Data Protection": ["Disk Encryption"],
            "🧑‍💻 User Account Management": ["Admin Rights Control", "Inactive User Removal"],
            "🛡️ Antivirus & Malware": ["Antivirus Installed", "Auto Scan Enabled", "Signature Updates"],
            "🌐 Web Security": ["Browser Hardening", "Pop-up Blocker", "HTTPS Enforced"],
            "📁 File & Folder Access": ["Access Permissions"],
            "📤 External Devices": ["USB Lock", "CD/DVD Access"],
            "🖥️ Display & Power Settings": ["Auto Screen Lock", "Display Timeout", "Power Saving"],
            "🗓 Audit Trails": ["Login/Logout Logs", "Security Log Retention", "Log File Encryption"],
            "📶 Wireless Configuration": ["WiFi", "Bluetooth", "Hotspot"],
            "🔑 Authentication": ["2FA Enabled", "Login Timeout", "Biometric Access"],
            "🔑system power": ["Restart", "Shut Down", "Refresh"],
        }

        self.stack_layout = QStackedLayout()
        for section, items in self.sections.items():
            self.sidebar.addItem(QListWidgetItem(section))
            content = QWidget()
            vbox = QVBoxLayout(content)
            vbox.addWidget(SectionBox(section, items, is_password=True))
            vbox.addStretch(1)
            self.stack_layout.addWidget(content)

        self.sidebar.currentRowChanged.connect(self.stack_layout.setCurrentIndex)

        content_layout.addWidget(self.sidebar)
        stack_widget = QWidget()
        stack_widget.setLayout(self.stack_layout)
        content_layout.addWidget(stack_widget)

        main_layout.addLayout(content_layout)

        bottom_layout = QVBoxLayout()

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(200)
        self.log_display.setStyleSheet("background-color: #f9f9f0; font-size: 10pt;")
        bottom_layout.addWidget(self.log_display)

        save_btn = QPushButton("\ud83d\udcbe Save Report as PDF")
        save_btn.setStyleSheet("background-color: #0078d7; color: white; padding: 8px; font-weight: bold;")
        save_btn.clicked.connect(self.save_report)
        bottom_layout.addWidget(save_btn, alignment=Qt.AlignRight)

        main_layout.addLayout(bottom_layout)

        footer = QHBoxLayout()
        self.theme_switch = QComboBox()
        self.theme_switch.addItems(["Light Mode ☀️", "Dark Mode 🌙"])
        self.theme_switch.currentIndexChanged.connect(self.change_theme)
    
        footer.addWidget(self.theme_switch)

        self.prev_audits_btn = QPushButton("\ud83d\udcc1 View Previous Audits")
        self.prev_audits_btn.clicked.connect(self.open_previous_audits)
        footer.addWidget(self.prev_audits_btn)

        self.refresh_btn = QPushButton("\ud83d\udd04 Refresh Logs")
        self.refresh_btn.clicked.connect(self.refresh_log)
        footer.addWidget(self.refresh_btn) 

        main_layout.addLayout(footer)
        self.sidebar.setCurrentRow(0)
        self.refresh_log()

    def refresh_log(self):
        self.log_display.setPlainText("\n".join(StatusRow.activity_log[-8:]))

    def save_report(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Save Report", "audit_report.pdf", "PDF Files (*.pdf)")
        if filepath:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt="External System Security Audit Report", ln=1, align="C")
            pdf.ln(5)
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 10, f"System Info: {self.system_info_label.text()}\n")
            pdf.multi_cell(0, 10, "Recent Activity Logs:")
            for entry in StatusRow.activity_log:
                pdf.multi_cell(0, 8, entry)
            pdf.output(filepath)
            QMessageBox.information(self, "Saved", f"PDF Report saved to {filepath}")

    def change_theme(self, index):
        if index == 0:
            self.setStyleSheet("")
        else:
            self.setStyleSheet("QWidget { background-color: #2e2e2e; color: black; } QPushButton { background-color: #444; color: white; }  system_info_label{color: black; font-size: 11pt; padding-bottom: 10px}")

    def open_previous_audits(self):
        folder = QFileDialog.getExistingDirectory(self, "Open Audit Reports Folder")
        if folder:
            QMessageBox.information(self, "Audit Reports", f"Browse your previous audit reports in:\n{folder}")


# ✅ System Power Controls
def handle_restart():
    try:
        subprocess.run(["shutdown", "/r", "/t", "0"], check=True)
    except Exception as e:
        QMessageBox.critical(None, "Restart Failed", f"Failed to restart: {e}")

def handle_shutdown():
    try:
        subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
    except Exception as e:
        QMessageBox.critical(None, "Shutdown Failed", f"Failed to shut down: {e}")

def handle_refresh():
    try:
        QMessageBox.information(None, "Refreshed", "System settings refreshed.")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        StatusRow.activity_log.append(f"{timestamp}: System refreshed.")
    except Exception as e:
        QMessageBox.critical(None, "Refresh Failed", f"Failed to refresh: {e}")



    

from PyQt5.QtWidgets import QDialog, QLineEdit, QLabel, QPushButton, QVBoxLayout

class LoginWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setFixedSize(300, 150)

        self.label = QLabel("Enter Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.check_password)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        self.setLayout(layout)

        self.correct_password = "admin123"  # ✅ Change this as needed

    def check_password(self):
        if self.password_input.text() == self.correct_password:
            self.accept()
        else:
            self.label.setText("Incorrect password. Try again.")
            self.password_input.clear()


def main():
    # Ensure the log folder exists for encryption
    log_folder = r"C:\AuditLogs"
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    app = QApplication(sys.argv)
    window = Dashboard()
    window.show()
    sys.exit(app.exec_())



def main():
    app = QApplication(sys.argv)

    login = LoginWindow()
    if login.exec_() == QDialog.Accepted:
        window = Dashboard()
        window.show()
        sys.exit(app.exec_())
if __name__ == "__main__":
    main()


# ✅ Main Security Policy Actions Dictionary
SECURITY_POLICY_ACTIONS = {
    "Audit Policy": lambda enable: run_powershell(
        r'C:\Windows\System32\auditpol.exe /set /category:"Logon/Logoff" '
        f'/success:{"enable" if enable else "disable"} /failure:{"enable" if enable else "disable"}'
    ),

    "Guest Account": lambda enable: run_powershell(
        r'C:\Windows\System32\net.exe user guest /active:' + ('yes' if enable else 'no')
    ), # type: ignore

    "Ctrl+Alt+Del": lambda enable: toggle_registry_value(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableCAD",
        winreg.REG_DWORD,
        0 if enable else 1
    ),

    "Display Last User": lambda enable: toggle_registry_value(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DontDisplayLastUserName",
        winreg.REG_DWORD,
        0 if enable else 1
    ),

    "Clear Virtual Memory": lambda enable: toggle_registry_value(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        "ClearPageFileAtShutdown",
        winreg.REG_DWORD,
        1 if enable else 0
    ),

    "2FA Enabled": lambda enable: toggle_registry_value(
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "scforceoption",
    winreg.REG_DWORD,
    1 if enable else 0
),

}




#net user guest   #to show the guest account status
#net user guest /active:yes   #to enable the guest account
#net user guest /active:no   #to disable the guest account
#auditpol /get /category:"Logon/Logoff"
#Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | 
#Select-Object DisableCAD, DontDisplayLastUserName

#Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" | 
#Select-Object ClearPageFileAtShutdown

#auditpol /get /category:"Logon/Logoff"
#powershell  #  wevtutil gl Security
#cipher /s:"C:\AuditLogs"

