"""
External System Security Audit - SLOG Solutions Pvt. Ltd.

v2: adds per-toggle confirmation dialogs with effect descriptions,
a "Revert All to Default" recovery button, light/dark theming, and a
reformatted PDF report.

Run on Windows with: python audit_dashboard.py
Requires: PyQt5, fpdf2, pywin32 (for winreg -- included with stock CPython on Windows)
"""

import sys
import platform
from datetime import datetime
import getpass
import os
import subprocess
import winreg
import ctypes
import json
import hashlib
import secrets

# Prevent console windows from flashing on Windows when spawning subprocesses
if platform.system() == "Windows":
    _original_popen = subprocess.Popen
    class PopenWithoutConsole(_original_popen):
        def __init__(self, *args, **kwargs):
            cflags = kwargs.get('creationflags', 0)
            cflags |= 0x08000000  # CREATE_NO_WINDOW
            kwargs['creationflags'] = cflags
            super().__init__(*args, **kwargs)
    subprocess.Popen = PopenWithoutConsole

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox,
    QPushButton, QDialog, QFormLayout, QLineEdit, QStackedLayout,
    QListWidget, QListWidgetItem, QTextEdit, QComboBox, QFileDialog,
    QMessageBox, QInputDialog, QFrame, QSizePolicy, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QFont, QColor
from fpdf import FPDF
from fpdf.enums import XPos, YPos



# ===========================================================================
# Low level helpers
# ===========================================================================

def is_app_dark():
    app = QApplication.instance()
    if app:
        for widget in app.topLevelWidgets():
            if hasattr(widget, "_is_dark"):
                return widget._is_dark
    return False


def is_admin():
    """Return True if the current process has Administrator rights."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Relaunch this script elevated, then exit the current (unprivileged) one."""
    try:
        params = " ".join(f'"{a}"' for a in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
    finally:
        sys.exit(0)


def require_admin(action_name):
    """Show a clear, consistent message when a privileged action is attempted
    without Administrator rights. Returns True if allowed to proceed."""
    if is_admin():
        return True
    QMessageBox.critical(
        None,
        "Administrator Rights Required",
        f"'{action_name}' requires Administrator privileges.\n\n"
        "Please close this app and relaunch it as Administrator."
    )
    return False


def run_powershell(command):
    """Run a PowerShell command, returning True on success."""
    powershell_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    result = subprocess.run(
        [powershell_path, "-Command", command],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[PowerShell error] {result.stderr.strip() or result.stdout.strip()}")
    return result.returncode == 0


def toggle_registry_value(path, name, value_type, value):
    """Write a value under HKEY_LOCAL_MACHINE. Requires admin rights."""
    if not require_admin(f"Set registry value '{name}'"):
        return False
    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            winreg.SetValueEx(key, name, 0, value_type, value)
        return True
    except Exception as e:
        print(f"[Registry error] {e}")
        return False


def toggle_current_user_registry_value(path, name, value_type, value):
    """Write a value under HKEY_CURRENT_USER (no admin rights needed)."""
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, name, 0, value_type, value)
        return True
    except Exception as e:
        print(f"[User registry error] {e}")
        return False
def read_registry_value(hive, path, name, default=None):
    """Best-effort registry read used for real-state status checks.
    Returns `default` if the key/value doesn't exist or can't be read."""
    try:
        with winreg.OpenKey(hive, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except Exception:
        return default



def log_activity(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    StatusRow.activity_log.append(f"{timestamp}: {message}")


# ===========================================================================
# Local config / password storage
#
# Password verification data is stored at:
#   %APPDATA%\CyberAuditTool\user_auth.json   (Windows)
# e.g. C:\Users\<you>\AppData\Roaming\CyberAuditTool\user_auth.json
#
# The file holds a JSON object: {"salt": "<hex>", "hash": "<hex>"}
# It is a PBKDF2-HMAC-SHA256 hash (200,000 iterations) with a random
# 16-byte salt -- the plaintext password itself is never written to disk.
# ===========================================================================

CONFIG_DIR = os.path.join(os.getenv("APPDATA") or os.getcwd(), "CyberAuditTool")
PASSWORD_FILE = os.path.join(CONFIG_DIR, "user_auth.json")
DEFAULT_PASSWORD = "admin123"
PBKDF2_ITERATIONS = 200000


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def load_password_data():
    try:
        with open(PASSWORD_FILE, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return None


def save_password_data(data):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(PASSWORD_FILE, "w", encoding="utf-8") as fp:
        json.dump(data, fp)


def ensure_password_file():
    """Create a default-password auth file on first run, and flag that a
    forced password change is needed (default credentials are not safe to
    keep, since DEFAULT_PASSWORD is visible to anyone reading this source)."""
    if not os.path.exists(PASSWORD_FILE):
        set_new_password(DEFAULT_PASSWORD)
        data = load_password_data() or {}
        data["must_change"] = True
        save_password_data(data)
        QMessageBox.information(
            None,
            "Setup Complete",
            f"A default password has been created: {DEFAULT_PASSWORD}\n\n"
            "You will be asked to change it now, before continuing."
        )


def password_must_be_changed():
    data = load_password_data()
    return bool(data and data.get("must_change"))


def verify_password(password):
    data = load_password_data()
    if not data or "salt" not in data or "hash" not in data:
        return False
    salt = data["salt"]
    _, candidate_hash = hash_password(password, salt=salt)
    return secrets.compare_digest(candidate_hash, data["hash"])


def set_new_password(password):
    salt, digest = hash_password(password)
    save_password_data({"salt": salt, "hash": digest, "must_change": False})
    log_activity("Application password changed.")


STATE_FILE = os.path.join(CONFIG_DIR, "system_audit_state.json")

def load_system_audit_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}

def save_system_audit_state(state):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as fp:
            json.dump(state, fp)
    except Exception as e:
        print(f"[Error] Failed to save state: {e}")


# ===========================================================================
# System power actions
# ===========================================================================

def handle_restart():
    try:
        subprocess.run(["shutdown", "/r", "/t", "0"], check=True)
        return True
    except Exception as e:
        QMessageBox.critical(None, "Restart Failed", f"Failed to restart: {e}")
        return False


def handle_shutdown():
    try:
        subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
        return True
    except Exception as e:
        QMessageBox.critical(None, "Shutdown Failed", f"Failed to shut down: {e}")
        return False


def handle_refresh():
    try:
        QMessageBox.information(None, "Refreshed", "System settings refreshed.")
        log_activity("System refreshed.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Refresh Failed", f"Failed to refresh: {e}")
        return False


def open_windows_update(enable=True):
    if enable:
        try:
            subprocess.run("start ms-settings:windowsupdate", shell=True, check=True)
            QMessageBox.information(None, "OS Patch Update", "Windows Update settings opened.")
            log_activity("Windows Update settings opened.")
            return True
        except Exception as e:
            QMessageBox.critical(None, "OS Patch Update Error", f"Failed to open Windows Update: {e}")
            return False
    QMessageBox.information(None, "OS Patch Update", "No action taken.")
    return True


def configure_account_lockout(enable=True):
    if not require_admin("Configure Account Lockout"):
        return False
    try:
        threshold = 3 if enable else 0
        cmd = f"net accounts /lockoutthreshold:{threshold}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or result.stdout.strip())
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Account Lockout", f"Account lockout has been {status}.")
        log_activity(f"Account lockout {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Account Lockout Error", f"Failed to configure account lockout: {e}")
        return False


def configure_password_policy(enable=True):
    if not require_admin("Configure Password Policy"):
        return False
    try:
        if enable:
            cmd = "net accounts /minpwlen:8 /maxpwage:45"
        else:
            cmd = "net accounts /minpwlen:0 /maxpwage:unlimited"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or result.stdout.strip())
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Password Policy", f"Password policy has been {status}.")
        log_activity(f"Password policy {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Password Policy Error", f"Failed to configure password policy: {e}")
        return False


def open_firewall_rules(enable=True):
    if enable:
        try:
            subprocess.run("start wf.msc", shell=True, check=True)
            QMessageBox.information(None, "Firewall Rules", "Windows Firewall with Advanced Security opened.")
            log_activity("Firewall rules opened.")
            return True
        except Exception as e:
            QMessageBox.critical(None, "Firewall Rules Error", f"Failed to open firewall rules: {e}")
            return False
    QMessageBox.information(None, "Firewall Rules", "No action taken.")
    return True


def simulate_feature(label, enabled):
    status = "enabled" if enabled else "disabled"
    QMessageBox.information(None, label, f"{label} has been {status}. (simulated)")
    log_activity(f"{label} {status} (simulated).")
    return True


# ===========================================================================
# BIOS (simulated - no real BIOS access is possible from Windows userspace)
# ===========================================================================

def simulate_bios_password(enable):
    status = "ENABLED" if enable else "DISABLED"
    print(f"[SIMULATION] BIOS password has been {status}.")
    log_activity(f"BIOS password {status}.")
    QMessageBox.information(None, "BIOS Password", f"BIOS password {status}.")
    return True


def simulate_bios_setting(setting, enabled):
    status = "ENABLED" if enabled else "DISABLED"
    print(f"[SIMULATION] BIOS Setting '{setting}' has been {status}.")
    log_activity(f"BIOS setting '{setting}' {status}.")
    QMessageBox.information(None, setting, f"{setting} has been {status} (simulated).")
    return True


# ===========================================================================
# Wireless adapter control
# ===========================================================================

def set_adapter_state(adapter_name, enable=True):
    if not require_admin("Toggle WiFi"):
        return False
    state = "enable" if enable else "disable"
    cmd = f'netsh interface set interface "{adapter_name}" {state}'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or result.stdout.strip() or "Unknown error")
        message = f"WiFi Adapter '{adapter_name}' has been {state}d. This change will persist until toggled again."
        print(f"[OK] {message}")
        QMessageBox.information(None, "WiFi", message)
        log_activity(f"WiFi Adapter '{adapter_name}' {state}d successfully. State persisted.")
        return True
    except subprocess.TimeoutExpired:
        print(f"[Error] Timeout while toggling adapter '{adapter_name}'")
        QMessageBox.critical(None, "WiFi Error", "Operation timed out.")
        return False
    except Exception as e:
        print(f"[Error] Failed to {state} adapter '{adapter_name}': {e}")
        QMessageBox.critical(None, "WiFi Error", f"Failed to {state} WiFi adapter: {e}")
        return False


def get_wifi_adapters():
    """List all WiFi/wireless adapters on the system."""
    try:
        cmd = 'netsh interface show interface'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            adapters = []
            for line in lines:
                if 'Wireless' in line or 'WiFi' in line or 'Wi-Fi' in line:
                    parts = line.split()
                    if len(parts) > 0:
                        adapters.append(parts[-1])
            return adapters if adapters else ['Wi-Fi']
    except Exception as e:
        print(f"[Error] Failed to get WiFi adapters: {e}")
    return ['Wi-Fi']


def toggle_bluetooth(enable=True):
    if not require_admin("Toggle Bluetooth"):
        return False
    try:
        if enable:
            script = (
                "Get-PnpDevice -Class Bluetooth | "
                "Where-Object { $_.InstanceId -like 'USB*' -or $_.InstanceId -like 'PCI*' -or $_.InstanceId -like 'ACPI*' } | "
                "Where-Object { $_.Status -ne 'OK' } | "
                "ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )
        else:
            script = (
                "Get-PnpDevice -Class Bluetooth | "
                "Where-Object { $_.InstanceId -like 'USB*' -or $_.InstanceId -like 'PCI*' -or $_.InstanceId -like 'ACPI*' } | "
                "Where-Object { $_.Status -eq 'OK' } | "
                "ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or "Failed to toggle Bluetooth")
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Bluetooth", f"Bluetooth has been {status}. This change will persist until toggled again.")
        log_activity(f"Bluetooth {status}. State persisted.")
        return True
    except subprocess.TimeoutExpired:
        QMessageBox.critical(None, "Bluetooth Error", "Operation timed out.")
        return False
    except Exception as e:
        QMessageBox.critical(None, "Bluetooth Error", f"Failed to toggle Bluetooth: {e}")
        return False


def toggle_hotspot(enable=True):
    if not require_admin("Toggle Hotspot"):
        return False
    try:
        action = "enable" if enable else "disable"
        ps_cmd = (
            "[Windows.System.UserProfile.LockScreen,Windows.System.UserProfile,ContentType=WindowsRuntime] | Out-Null; "
            "Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
            "$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]; "
            "Function Await($WinRtTask, $ResultType) { "
            "  $asTask = $asTaskGeneric.MakeGenericMethod($ResultType); "
            "  $netTask = $asTask.Invoke($null, @($WinRtTask)); "
            "  $netTask.Wait(-1) | Out-Null; "
            "  $netTask.Result; "
            "}; "
            "$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile(); "
            "$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile); "
            f"if ($tetheringManager) {{ "
            f"  if ('{action}' -eq 'enable') {{ "
            "    $res = Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]); "
            "    Write-Output $res.Status; "
            "  } else { "
            "    $res = Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]); "
            "    Write-Output $res.Status; "
            "  } "
            "} else { "
            "  Write-Error 'TetheringManager not available'; "
            "}"
        )
        result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or "Failed to toggle Hotspot (TetheringManager error)")
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Hotspot", f"Hotspot has been {status}. This change will persist until toggled again.")
        log_activity(f"Hotspot {status}. State persisted.")
        return True
    except subprocess.TimeoutExpired:
        QMessageBox.critical(None, "Hotspot Error", "Operation timed out.")
        return False
    except Exception as e:
        QMessageBox.critical(None, "Hotspot Error", f"Failed to toggle Hotspot: {e}")
        return False


def toggle_cd_dvd_access(enable=True):
    if not require_admin("Toggle CD/DVD Access"):
        return False
    try:
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
        log_activity(f"CD/DVD Access {status}.")
        return True
    except subprocess.CalledProcessError as e:
        QMessageBox.critical(None, "CD/DVD Error", f"Failed to toggle CD/DVD access: {e}")
        return False


def toggle_usb_adapter(enable=True):
    if not require_admin("Toggle USB Devices"):
        return False
    try:
        if enable:
            script = (
                "Get-PnpDevice | Where-Object { $_.Class -eq 'USB' -and $_.Status -ne 'OK' } | "
                "ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )
        else:
            script = (
                "Get-PnpDevice | Where-Object { $_.Class -eq 'USB' -and $_.Status -eq 'OK' } | "
                "ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
            )
        subprocess.run(["powershell", "-Command", script], check=True)
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "USB Adapter", f"USB ports have been {status}.")
        log_activity(f"USB Adapter {status}.")
        return True
    except subprocess.CalledProcessError as e:
        QMessageBox.critical(None, "USB Toggle Error", f"Failed to toggle USB: {e}")
        return False


# ===========================================================================
# OS / network / security toggles
# ===========================================================================

def toggle_firewall(enable=True):
    if not require_admin("Toggle Windows Firewall"):
        return False
    try:
        cmd = f'netsh advfirewall set allprofiles state {"on" if enable else "off"}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or result.stdout.strip() or "Unknown error")
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Firewall", f"Windows Firewall has been {status}.")
        log_activity(f"Windows Firewall {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Firewall Error", f"Failed to update firewall status: {e}")
        return False


def toggle_admin_rights(enable=True):
    if not require_admin("Change Admin Rights"):
        return False
    try:
        username = getpass.getuser()
        cmd = f'net localgroup Administrators "{username}" /{"add" if enable else "delete"}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip())
        status = "granted" if enable else "revoked"
        QMessageBox.information(None, "Admin Rights", f"Admin rights have been {status} for user: {username}")
        log_activity(f"Admin rights {status} for user {username}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Admin Rights Error", f"Failed to change admin rights: {e}")
        return False


def toggle_antivirus_check(enable=True):
    try:
        if enable:
            command = (
                "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntivirusProduct | "
                "Select-Object -Property displayName,productState"
            )
            result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
            if result.returncode != 0 or not result.stdout.strip():
                QMessageBox.critical(None, "Antivirus Status", "No antivirus detected or query failed.")
                return False
            QMessageBox.information(None, "Antivirus Status", f"Antivirus Detected:\n{result.stdout.strip()}")
            log_activity(f"Antivirus check performed. Detected:\n{result.stdout.strip()}")
        else:
            QMessageBox.information(None, "Antivirus Check", "Antivirus check is disabled (no status will be shown).")
            log_activity("Antivirus check disabled.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Antivirus Check Failed", f"Error: {e}")
        return False


def toggle_auto_scan(enable=True):
    if not require_admin("Toggle Auto Scan"):
        return False
    try:
        command = f"Set-MpPreference -DisableRealtimeMonitoring:{'false' if enable else 'true'}"
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip())
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Auto Scan", f"Auto Scan (Real-time Protection) has been {status}.")
        log_activity(f"Auto Scan {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Auto Scan Error", f"Failed to toggle Auto Scan: {e}")
        return False


def toggle_signature_update(enable=True):
    if not require_admin("Update Virus Signatures"):
        return False
    try:
        if enable:
            command = "Update-MpSignature"
            result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(result.stderr.strip())
            QMessageBox.information(None, "Signature Update", "Virus signatures have been updated successfully.")
            status = "updated"
        else:
            QMessageBox.information(None, "Signature Update", "Signature update skipped.")
            status = "skipped"
        log_activity(f"Signature update {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Signature Update Error", f"Failed to update signatures: {e}")
        return False


def toggle_inactive_user_removal(enable=True):
    if not require_admin("Remove Inactive Users"):
        return False
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
        log_activity(f"Inactive user removal result: {output}")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Inactive User Error", f"Failed to remove inactive users: {e}")
        return False


def toggle_disk_encryption(enable=True):
    if not require_admin("Change Disk Encryption (BitLocker)"):
        return False
    try:
        drive = "C:"
        if enable:
            check_cmd = f'Get-BitLockerVolume -MountPoint "{drive}" | Select-Object VolumeStatus'
            result = subprocess.run(["powershell", "-Command", check_cmd], capture_output=True, text=True)
            if "FullyEncrypted" in result.stdout:
                QMessageBox.information(None, "Disk Encryption", "Disk is already encrypted.")
                return True
            cmd = (
                f'Enable-BitLocker -MountPoint "{drive}" '
                '-EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmProtector'
            )
        else:
            cmd = f'Disable-BitLocker -MountPoint "{drive}"'

        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip())
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Disk Encryption", f"BitLocker has been {status} on {drive}.")
        log_activity(f"Disk encryption {status} on {drive}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Disk Encryption Error", f"Failed: {e}")
        return False


def toggle_backup_schedule(enable=True):
    if not require_admin("Change Backup Schedule"):
        return False
    try:
        task_name = "CyberAuditDataBackup"
        script_path = r"C:\CyberAudit\backup_script.ps1"
        if enable:
            cmd = (
                f'schtasks /Create /TN "{task_name}" /TR "powershell -ExecutionPolicy Bypass -File \\"{script_path}\\"" '
                '/SC DAILY /ST 18:00 /RL HIGHEST /F'
            )
        else:
            cmd = f'schtasks /Delete /TN "{task_name}" /F'

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr.strip())
        status = "scheduled" if enable else "canceled"
        QMessageBox.information(None, "Backup Schedule", f"Backup task has been {status} successfully.")
        log_activity(f"Data backup schedule {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Backup Schedule Error", f"Failed to update schedule: {e}")
        return False


def toggle_browser_hardening(enable=True):
    if not require_admin("Apply Browser Hardening"):
        return False
    try:
        chrome_path = r"SOFTWARE\Policies\Google\Chrome"
        edge_path = r"SOFTWARE\Policies\Microsoft\Edge"

        policies = {
            "IncognitoModeAvailability": 1 if enable else 0,   # 1 = disable Incognito
            "DefaultJavaScriptSetting": 2 if enable else 1,     # 2 = block JS, 1 = allow
            "DefaultPopupsSetting": 2 if enable else 1,         # 2 = block, 1 = allow
        }

        for path in [chrome_path, edge_path]:
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
                for name, value in policies.items():
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            except Exception as e:
                print(f"[Error] Failed to write registry for {path}: {e}")
                return False

        QMessageBox.information(
            None, "Browser Hardening",
            "Browser hardening has been applied.\nPlease restart your browser.\nTo verify, go to: chrome://policy"
        )
        log_activity(f"Browser Hardening {'enabled' if enable else 'disabled'}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Hardening Error", f"Browser Hardening Failed: {e}")
        return False


def toggle_popup_blocker(enable=True):
    if not require_admin("Toggle Pop-up Blocker"):
        return False
    try:
        chrome_path = r"SOFTWARE\Policies\Google\Chrome"
        edge_path = r"SOFTWARE\Policies\Microsoft\Edge"
        value = 2 if enable else 1  # 2 = block pop-ups, 1 = allow

        for browser_path in [chrome_path, edge_path]:
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, browser_path)
                winreg.SetValueEx(key, "DefaultPopupsSetting", 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            except Exception as e:
                print(f"[Registry error] {browser_path}: {e}")
                return False

        status = "enabled" if enable else "disabled"
        QMessageBox.information(
            None, "Pop-up Blocker",
            f"Pop-up blocker has been {status}.\nRestart Chrome, then visit chrome://policy to verify."
        )
        log_activity(f"Pop-up Blocker {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Pop-up Blocker Error", f"Failed: {e}")
        return False


def toggle_https_enforced(enable=True):
    if not require_admin("Toggle HTTPS Enforcement"):
        return False
    try:
        chrome_path = r"SOFTWARE\Policies\Google\Chrome"
        edge_path = r"SOFTWARE\Policies\Microsoft\Edge"
        value = 1 if enable else 0

        for browser_path in [chrome_path, edge_path]:
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, browser_path)
                winreg.SetValueEx(key, "ForceHTTPS", 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            except Exception as e:
                print(f"[Error] Failed to write to {browser_path}: {e}")
                return False

        status = "enabled" if enable else "disabled"
        QMessageBox.information(
            None, "HTTPS Enforced",
            f"HTTPS Enforcement has been {status}.\nRestart Chrome or Edge and visit chrome://policy to verify."
        )
        log_activity(f"HTTPS Enforced {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "HTTPS Enforcement Error", f"Failed to apply setting: {e}")
        return False


def toggle_folder_access_control(enable=True):
    if not require_admin("Change Folder Access Control"):
        return False
    folder_path = r"C:\SecureFolder"
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path)
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Failed to create folder: {e}")
            return False
    try:
        if enable:
            cmd = f'icacls "{folder_path}" /grant Everyone:(F) /T /C'
        else:
            cmd = f'icacls "{folder_path}" /deny Everyone:(F) /T /C'
        subprocess.run(cmd, shell=True, check=True)
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Folder Access", f"Access to {folder_path} has been {status}.")
        log_activity(f"File/Folder access {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Folder Access Error", f"Failed to toggle folder access: {e}")
        return False


def set_display_timeout(enable=True):
    try:
        minutes = 5 if enable else 0
        subprocess.run(["powercfg", "/change", "monitor-timeout-ac", str(minutes)], check=True)
        subprocess.run(["powercfg", "/change", "monitor-timeout-dc", str(minutes)], check=True)
        return True
    except Exception as e:
        print(f"[Error] Failed to set display timeout: {e}")
        return False


def set_power_saving_mode(enable=True):
    try:
        scheme = "a1841308-3541-4fab-bc81-f71556f20b4a" if enable else "381b4222-f694-41f0-9685-ff5bb260df2e"
        subprocess.run(["powercfg", "/setactive", scheme], check=True)
        return True
    except Exception as e:
        print(f"[Error] Failed to set power scheme: {e}")
        return False


def toggle_win_password(enable=True):
    if not require_admin("Configure Windows Password"):
        return False
    try:
        username = getpass.getuser()
        state = "$true" if enable else "$false"
        script = f"Set-LocalUser -Name '{username}' -PasswordRequired {state}"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or "Failed to set password requirement")
        status = "required" if enable else "not required"
        QMessageBox.information(None, "Windows Password", f"Password is now {status} for account '{username}'.")
        log_activity(f"Windows password requirements set to {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Windows Password Error", f"Failed: {e}")
        return False


def toggle_welcome_screen(enable=True):
    if not require_admin("Toggle Welcome Screen"):
        return False
    val = 0 if enable else 1
    success = toggle_registry_value(
        r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
        "NoLockScreen", winreg.REG_DWORD, val
    )
    if success:
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Welcome Screen", f"Welcome/Lock Screen has been {status}.")
        log_activity(f"Welcome/Lock Screen {status}.")
        return True
    return False


def toggle_lan_cards_shortcut():
    try:
        subprocess.run("start ncpa.cpl", shell=True, check=True)
        QMessageBox.information(None, "Network Connections", "Network Connections control panel opened.")
        log_activity("Network Connections panel opened.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Network Connections Error", f"Failed: {e}")
        return False


def toggle_os_activation_shortcut():
    try:
        subprocess.run("start ms-settings:activation", shell=True, check=True)
        QMessageBox.information(None, "Activation Settings", "Windows Activation Settings opened.")
        log_activity("Activation settings opened.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Activation Error", f"Failed: {e}")
        return False


def toggle_malware_scan_trigger():
    try:
        QMessageBox.information(None, "Malware Scan", "Triggering Windows Defender Quick Scan in the background...")
        subprocess.Popen(["powershell", "-Command", "Start-MpScan -ScanType QuickScan"])
        log_activity("Windows Defender quick scan triggered.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Malware Scan Error", f"Failed: {e}")
        return False


def toggle_non_adn_shortcut():
    try:
        subprocess.run("start resmon", shell=True, check=True)
        QMessageBox.information(None, "Resource Monitor", "Resource Monitor opened (Network tab is recommended for checking established connections).")
        log_activity("Resource Monitor opened.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Resource Monitor Error", f"Failed: {e}")
        return False


def toggle_unwanted_sw_shortcut():
    try:
        subprocess.run("start appwiz.cpl", shell=True, check=True)
        QMessageBox.information(None, "Programs & Features", "Programs & Features control panel opened to inspect installed software.")
        log_activity("Programs & Features panel opened.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Programs & Features Error", f"Failed: {e}")
        return False


def toggle_domain_joined_shortcut():
    try:
        subprocess.run("start sysdm.cpl", shell=True, check=True)
        QMessageBox.information(None, "System Properties", "System Properties opened to verify domain join settings.")
        log_activity("System Properties opened.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "System Properties Error", f"Failed: {e}")
        return False


def toggle_ipv6_disabled(enable=True):
    if not require_admin("Toggle IPv6"):
        return False
    try:
        state = "$false" if enable else "$true"
        script = f"Set-NetAdapterBinding -Name * -ComponentID ms_tcpip6 -Enabled {state}"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or "Failed to configure IPv6 binding")
        status = "disabled" if enable else "enabled"
        QMessageBox.information(None, "IPv6 Configuration", f"IPv6 protocol has been {status} on all network adapters.")
        log_activity(f"IPv6 protocol {status} on adapters.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "IPv6 Configuration Error", f"Failed to toggle IPv6: {e}")
        return False


def toggle_folder_sharing(enable=True):
    if not require_admin("Toggle Folder Sharing"):
        return False
    try:
        if enable:
            script = "Set-Service -Name LanmanServer -StartupType Automatic; Start-Service -Name LanmanServer -ErrorAction SilentlyContinue"
        else:
            script = "Stop-Service -Name LanmanServer -Force; Set-Service -Name LanmanServer -StartupType Disabled"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or "Failed to configure sharing service")
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Folder Sharing", f"Folder sharing capability has been {status}.")
        log_activity(f"Folder sharing capability {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Folder Sharing Error", f"Failed: {e}")
        return False


def toggle_default_shares(enable=True):
    if not require_admin("Toggle Default Shares"):
        return False
    val = 1 if enable else 0
    success = toggle_registry_value(
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "AutoShareWks", winreg.REG_DWORD, val
    )
    if success:
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Default Shares", f"Default administrative shares (C$, ADMIN$) have been {status}.\n(Requires system restart to take effect)")
        log_activity(f"Default administrative shares {status}.")
        return True
    return False


def toggle_rename_admin(enable=True):
    if not require_admin("Rename Administrator Account"):
        return False
    try:
        script_get = "(Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Name"
        res = subprocess.run(["powershell", "-Command", script_get], capture_output=True, text=True, timeout=5)
        if res.returncode != 0 or not res.stdout.strip():
            raise Exception("Could not locate local administrator account.")
        current_name = res.stdout.strip()
        
        if enable:
            if current_name.lower() == "administrator":
                new_name = "SecAdmin"
                script_rename = f'Rename-LocalUser -Name "{current_name}" -NewName "{new_name}"'
                res_rename = subprocess.run(["powershell", "-Command", script_rename], capture_output=True, text=True, timeout=10)
                if res_rename.returncode != 0:
                    raise Exception(res_rename.stderr.strip() or "Rename command failed.")
                QMessageBox.information(None, "Rename Administrator", f"Built-in Administrator account renamed to '{new_name}'.")
                log_activity(f"Administrator renamed to '{new_name}'.")
            else:
                QMessageBox.information(None, "Rename Administrator", f"Administrator account is already renamed to '{current_name}'.")
        else:
            if current_name.lower() != "administrator":
                new_name = "Administrator"
                script_rename = f'Rename-LocalUser -Name "{current_name}" -NewName "{new_name}"'
                res_rename = subprocess.run(["powershell", "-Command", script_rename], capture_output=True, text=True, timeout=10)
                if res_rename.returncode != 0:
                    raise Exception(res_rename.stderr.strip() or "Rename command failed.")
                QMessageBox.information(None, "Rename Administrator", f"Administrator account renamed back to default '{new_name}'.")
                log_activity("Administrator renamed back to default 'Administrator'.")
            else:
                QMessageBox.information(None, "Rename Administrator", "Administrator account is already using the default name.")
        return True
    except Exception as e:
        QMessageBox.critical(None, "Rename Administrator Error", f"Failed: {e}")
        return False


def toggle_service_state(service_name, display_name, enable=True):
    if not require_admin(f"Configure {display_name}"):
        return False
    try:
        if enable:
            script = f"Set-Service -Name {service_name} -StartupType Automatic; Start-Service -Name {service_name} -ErrorAction SilentlyContinue"
        else:
            script = f"Stop-Service -Name {service_name} -Force; Set-Service -Name {service_name} -StartupType Disabled"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or f"Failed to change state of {service_name}")
        status = "started/enabled" if enable else "stopped/disabled"
        QMessageBox.information(None, display_name, f"Service '{display_name}' has been {status}.")
        log_activity(f"Service '{display_name}' {status}.")
        return True
    except Exception as e:
        QMessageBox.critical(None, f"{display_name} Error", f"Failed: {e}")
        return False


def toggle_remote_assistance(enable=True):
    if not require_admin("Toggle Remote Assistance"):
        return False
    success = toggle_registry_value(
        r"System\CurrentControlSet\Control\Terminal Server",
        "fAllowToGetHelp", winreg.REG_DWORD, 1 if enable else 0
    )
    if success:
        status = "enabled" if enable else "disabled"
        QMessageBox.information(None, "Remote Assistance", f"Remote Assistance has been {status}.")
        log_activity(f"Remote Assistance {status}.")
        return True
    return False


# ===========================================================================
# Security policy registry: maps a section label -> the function that
# applies it. Every key here must exactly match a label used in
# Dashboard.sections below.
# ===========================================================================

SECURITY_POLICY_ACTIONS = {
    "Audit Policy": lambda enable: run_powershell(
        'auditpol /set /category:"Logon/Logoff" '
        f'/success:{"enable" if enable else "disable"} /failure:{"enable" if enable else "disable"}'
    ),
    "Guest Account": lambda enable: run_powershell(
        "net user guest /active:" + ("yes" if enable else "no")
    ),
    "Ctrl+Alt+Del": lambda enable: toggle_registry_value(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableCAD", winreg.REG_DWORD, 0 if enable else 1
    ),
    "Display Last User": lambda enable: toggle_registry_value(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DontDisplayLastUserName", winreg.REG_DWORD, 0 if enable else 1
    ),
    "Clear Virtual Memory": lambda enable: toggle_registry_value(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        "ClearPageFileAtShutdown", winreg.REG_DWORD, 1 if enable else 0
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
    "OS Patch Update": lambda enable: open_windows_update(enable),
    "Account Lockout": lambda enable: configure_account_lockout(enable),
    "Password Policy": lambda enable: configure_password_policy(enable),
    "Firewall Rules": lambda enable: open_firewall_rules(enable),
    "Disable Unused Ports": lambda enable: simulate_feature("Disable Unused Ports", enable),
    "Configure VLANs": lambda enable: simulate_feature("Configure VLANs", enable),
    "MAC Filtering": lambda enable: simulate_feature("MAC Filtering", enable),

    "Biometric Access": lambda enable: toggle_registry_value(
        r"SOFTWARE\Policies\Microsoft\Biometrics",
        "Enabled", winreg.REG_DWORD, 1 if enable else 0
    ),
    "USB Lock": lambda enable: toggle_usb_adapter(not enable),
    "CD/DVD Access": lambda enable: toggle_cd_dvd_access(enable),
    "Display Timeout": lambda enable: set_display_timeout(enable),
    "Power Saving Mode": lambda enable: set_power_saving_mode(enable),

    "Login Timeout": lambda enable: toggle_registry_value(
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "MaxIdleTime", winreg.REG_DWORD, 300000 if enable else 0
    ),
    "2FA Enabled": lambda enable: toggle_registry_value(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "scforceoption", winreg.REG_DWORD, 1 if enable else 0
    ),
    "Screen Saver Password": lambda enable: (
        toggle_current_user_registry_value(
            r"Control Panel\Desktop", "ScreenSaverIsSecure", winreg.REG_SZ, "1" if enable else "0"
        ) and
        toggle_current_user_registry_value(
            r"Control Panel\Desktop", "ScreenSaveTimeOut", winreg.REG_SZ, "300" if enable else "0"
        )
    ),

    "Login/Logout Logs": lambda enable: run_powershell(
        'auditpol /set /category:"Logon/Logoff" '
        f'/success:{"enable" if enable else "disable"} /failure:{"enable" if enable else "disable"}'
    ),
    "Security Log Retention": lambda enable: run_powershell(
        f'wevtutil sl Security /rt:{"true" if enable else "false"}'
    ),
    "Log File Encryption": lambda enable: run_powershell(
        f'cipher /{"E" if enable else "D"} /A /S:"C:\\AuditLogs"'
    ),

    "BIOS Password": lambda enable: simulate_bios_password(enable),
    "Boot Order Lock": lambda enable: simulate_bios_setting("Boot Order Lock", enable),
    "Secure Boot": lambda enable: simulate_bios_setting("Secure Boot", enable),
    "BIOS Card Reader Disabled": lambda enable: simulate_bios_setting("BIOS Card Reader Disabled", enable),
    "BIOS Wireless NW Disabled": lambda enable: simulate_bios_setting("BIOS Wireless NW Disabled", enable),
    "BIOS Multiple NW Card Disabled": lambda enable: simulate_bios_setting("BIOS Multiple NW Card Disabled", enable),
    "BIOS Multiple Booting Disabled": lambda enable: simulate_bios_setting("BIOS Multiple Booting Disabled", enable),
    "BIOS Wake on LAN Disabled": lambda enable: simulate_bios_setting("BIOS Wake on LAN Disabled", enable),
    "BIOS Chassis Intrusion Enabled": lambda enable: simulate_bios_setting("BIOS Chassis Intrusion Enabled", enable),
    "BIOS Updated": lambda enable: simulate_bios_setting("BIOS Updated", enable),
    "IPv6 Disabled": lambda enable: toggle_ipv6_disabled(enable),
    "Folder Sharing": lambda enable: toggle_folder_sharing(enable),
    "Default Share": lambda enable: toggle_default_shares(enable),
    "Administrator Renamed": lambda enable: toggle_rename_admin(enable),
    "Bluetooth Support Service": lambda enable: toggle_service_state("bthserv", "Bluetooth Support Service", enable),
    "Computer Browser": lambda enable: toggle_service_state("Browser", "Computer Browser", enable),
    "Distributed Link Tracking": lambda enable: toggle_service_state("TrkWks", "Distributed Link Tracking", enable),
    "Fax Service": lambda enable: toggle_service_state("Fax", "Fax Service", enable),
    "FTP Publishing": lambda enable: toggle_service_state("FTPSVC", "FTP Publishing", enable),
    "IP Helper": lambda enable: toggle_service_state("iphlpsvc", "IP Helper", enable),
    "IIS Admin Service": lambda enable: toggle_service_state("IISADMIN", "IIS Admin Service", enable),
    "Remote Registry": lambda enable: toggle_service_state("RemoteRegistry", "Remote Registry", enable),
    "Routing & Remote Access": lambda enable: toggle_service_state("RemoteAccess", "Routing & Remote Access", enable),
    "SSDP Discovery": lambda enable: toggle_service_state("SSDPSRV", "SSDP Discovery", enable),
    "SNMP Service": lambda enable: toggle_service_state("SNMP", "SNMP Service", enable),
    "Telnet Service": lambda enable: toggle_service_state("TlntSvr", "Telnet Service", enable),
    "Remote Assistance": lambda enable: toggle_remote_assistance(enable),
    "Win Password": lambda enable: toggle_win_password(enable),
    "Welcome Screen": lambda enable: toggle_welcome_screen(enable),
    "No of LAN Cards": lambda enable: toggle_lan_cards_shortcut(),
    "OS Activation Status": lambda enable: toggle_os_activation_shortcut(),
    "Malware Scan Check": lambda enable: toggle_malware_scan_trigger(),
    "Non-ADN IP Connections": lambda enable: toggle_non_adn_shortcut(),
    "Unwanted Software Scan": lambda enable: toggle_unwanted_sw_shortcut(),
    "Domain Joined Status": lambda enable: toggle_domain_joined_shortcut(),
    "SCCM Installed": lambda enable: simulate_feature("SCCM Installed", enable),
    "No of User Account Present": lambda enable: run_powershell("start lusrmgr.msc"),
    "Usage of Admin Acct for Daily Wk": lambda enable: toggle_admin_rights(not enable),

    "Netmeeting Remote Desktop": lambda enable: toggle_service_state("mnmsrvc", "Netmeeting Remote Desktop", enable),
    "Remote Auto Connection Manager": lambda enable: toggle_service_state("RasAuto", "Remote Auto Connection Manager", enable),
    "Remote Desktop": lambda enable: toggle_service_state("TermService", "Remote Desktop", enable),
    "Wireless Service": lambda enable: toggle_service_state("WlanSvc", "Wireless Service", enable),

    "USB Mass Storage Auditing": lambda enable: toggle_registry_value(
        r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start", winreg.REG_DWORD, 3 if enable else 4
    ),
    "Air Gap Compliance": lambda enable: run_powershell(
        "Get-NetAdapter | Disable-NetAdapter -Confirm:$false" if enable else "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"
    ),
    "Classified Data Scan": lambda enable: simulate_feature("Classified Data Scan", enable),
    "Media Files Compliance": lambda enable: simulate_feature("Media Files Compliance", enable),
    "System Time Sync": lambda enable: (
        toggle_service_state("w32time", "Windows Time", enable) and
        toggle_registry_value(r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "Type", winreg.REG_SZ, "NTP" if enable else "NoSync")
    ),
    "Computer Naming Compliance": lambda enable: simulate_feature("Computer Naming Compliance", enable),
    "Physical Asset Labeling": lambda enable: simulate_feature("Physical Asset Labeling", enable),
    "Audit Evidence Collection": lambda enable: simulate_feature("Audit Evidence Collection", enable),
}


# ===========================================================================
# Default ("safe baseline") state per toggle, used by "Revert All to Default".
# True  = the recommended/secure state is ENABLED for this control
# False = the recommended/secure state is DISABLED for this control
#
# These defaults follow common hardening guidance (CIS-style baselines):
# protective controls default ON, risk-introducing controls default OFF.
# Edit this dict to match your organization's actual baseline policy.
# ===========================================================================

DEFAULT_STATE = {
    "BIOS Password": True,
    "Boot Order Lock": True,
    "Secure Boot": True,
    "OS Patch Update": True,
    "Firewall Enabled": True,
    "Account Lockout": True,
    "Password Policy": True,
    "Guest Account": False,
    "Audit Policy": True,
    "Ctrl+Alt+Del": True,
    "Display Last User": False,
    "Clear Virtual Memory": True,
    "Disable Unused Ports": True,
    "Configure VLANs": True,
    "Firewall Rules": True,
    "MAC Filtering": True,
    "Disk Encryption": True,
    "Admin Rights Control": False,
    "Inactive User Removal": True,
    "Antivirus Installed": True,
    "Auto Scan Enabled": True,
    "Signature Updates": True,
    "Browser Hardening": True,
    "Pop-up Blocker": True,
    "HTTPS Enforced": True,
    "Access Permissions": False,
    "USB Lock": False,
    "CD/DVD Access": True,
    "Screen Saver Password": True,
    "Display Timeout": True,
    "Power Saving Mode": False,
    "Login/Logout Logs": True,
    "Security Log Retention": True,
    "Log File Encryption": True,
    "WiFi": True,
    "Bluetooth": False,
    "Hotspot": False,
    "2FA Enabled": True,
    "Login Timeout": True,
    "Biometric Access": True,
    "BIOS Card Reader Disabled": True,
    "BIOS Wireless NW Disabled": True,
    "BIOS Multiple NW Card Disabled": True,
    "BIOS Multiple Booting Disabled": True,
    "BIOS Wake on LAN Disabled": True,
    "BIOS Chassis Intrusion Enabled": True,
    "BIOS Updated": True,
    "IPv6 Disabled": True,
    "Folder Sharing": False,
    "Default Share": False,
    "Administrator Renamed": True,
    "Bluetooth Support Service": False,
    "Computer Browser": False,
    "Distributed Link Tracking": False,
    "Fax Service": False,
    "FTP Publishing": False,
    "IP Helper": False,
    "IIS Admin Service": False,
    "Remote Registry": False,
    "Routing & Remote Access": False,
    "SSDP Discovery": False,
    "SNMP Service": False,
    "Telnet Service": False,
    "Remote Assistance": False,
    "Win Password": True,
    "Welcome Screen": True,
    "No of LAN Cards": True,
    "OS Activation Status": True,
    "Malware Scan Check": True,
    "Non-ADN IP Connections": True,
    "Unwanted Software Scan": True,
    "Domain Joined Status": True,
    "SCCM Installed": True,
    "No of User Account Present": True,
    "Usage of Admin Acct for Daily Wk": True,

    "Netmeeting Remote Desktop": False,
    "Remote Auto Connection Manager": False,
    "Remote Desktop": False,
    "Wireless Service": True,

    "USB Mass Storage Auditing": True,
    "Air Gap Compliance": True,
    "Classified Data Scan": True,
    "Media Files Compliance": True,
    "System Time Sync": True,
    "Computer Naming Compliance": True,
    "Physical Asset Labeling": True,
    "Audit Evidence Collection": True,
}



# ===========================================================================
# Status Query Helper Functions
# ===========================================================================

def get_wifi_real_state():
    """Best-effort real WiFi adapter enabled/disabled check."""
    try:
        result = subprocess.run('netsh interface show interface', shell=True,
                                 capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return None
        for line in result.stdout.split('\n'):
            line_lower = line.lower()
            if 'wireless' in line_lower or 'wifi' in line_lower or 'wi-fi' in line_lower:
                parts = line.split(maxsplit=3)
                if len(parts) >= 4:
                    admin_state = parts[0].lower()
                    if admin_state == 'enabled':
                        return True
                    elif admin_state == 'disabled':
                        return False
        return None
    except Exception:
        return None


def get_bluetooth_real_state():
    """True if the physical Bluetooth adapter has Status 'OK'."""
    script = (
        "Get-PnpDevice -Class Bluetooth | "
        "Where-Object { $_.InstanceId -like 'USB*' -or $_.InstanceId -like 'PCI*' -or $_.InstanceId -like 'ACPI*' } | "
        "Where-Object { $_.Status -eq 'OK' } | "
        "Measure-Object | Select-Object -ExpandProperty Count"
    )
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip()) > 0
    except Exception:
        return None


def get_hotspot_real_state():
    script = (
        "$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()\n"
        "$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)\n"
        "$tetheringManager.TetheringOperationalState"
    )
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    state = result.stdout.strip().lower()
    if state == "on":
        return True
    if state == "off":
        return False
    return None


def get_firewall_real_state():
    script = "(Get-NetFirewallProfile -All | Where-Object {$_.Enabled -eq $true} | Measure-Object).Count"
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip()) > 0
    except Exception:
        return None


def get_admin_rights_real_state():
    try:
        username = getpass.getuser()
        script = f'(Get-LocalGroupMember -Group "Administrators" | Where-Object {{$_.Name -like "*{username}"}} | Measure-Object).Count'
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
        if result.returncode != 0:
            return None
        return int(result.stdout.strip()) > 0
    except Exception:
        return None


def get_antivirus_real_state():
    script = "(Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntivirusProduct | Measure-Object).Count"
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip()) > 0
    except Exception:
        return None


def get_auto_scan_real_state():
    script = "(Get-MpPreference).DisableRealtimeMonitoring"
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    return result.stdout.strip().lower() == "false"


def get_disk_encryption_real_state():
    script = '(Get-BitLockerVolume -MountPoint "C:").VolumeStatus'
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    return "FullyEncrypted" in result.stdout


def get_secure_boot_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                               "UEFISecureBootEnabled")
    return (val == 1) if val is not None else None


def get_net_accounts_data():
    powershell_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    result = subprocess.run([powershell_path, "-Command", "net accounts"], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return {}
    data = {}
    for line in result.stdout.splitlines():
        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            data[key] = val
    return data


def get_account_lockout_real_state():
    data = get_net_accounts_data()
    threshold_str = data.get("Lockout threshold")
    if not threshold_str:
        return None
    if threshold_str.lower() == "never":
        return False
    try:
        return int(threshold_str) > 0
    except Exception:
        return None


def get_password_policy_real_state():
    data = get_net_accounts_data()
    min_len_str = data.get("Minimum password length")
    max_age_str = data.get("Maximum password age (days)")
    if min_len_str is None or max_age_str is None:
        return None
    try:
        min_len = int(min_len_str)
        if max_age_str.lower() == "unlimited":
            return False
        max_age = int(max_age_str)
        return min_len >= 8 and max_age <= 45
    except Exception:
        return None


def get_clear_virtual_memory_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                               "ClearPageFileAtShutdown")
    return (val == 1) if val is not None else None


def get_browser_hardening_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Policies\Google\Chrome",
                               "IncognitoModeAvailability")
    return (val == 1) if val is not None else None


def get_popup_blocker_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Policies\Google\Chrome",
                               "DefaultPopupsSetting")
    return (val == 2) if val is not None else None


def get_https_enforced_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Policies\Google\Chrome",
                               "ForceHTTPS")
    return (val == 1) if val is not None else None


def get_auto_screen_lock_real_state():
    val = read_registry_value(winreg.HKEY_CURRENT_USER,
                               r"Control Panel\Desktop",
                               "ScreenSaverIsSecure")
    return (val == "1") if val is not None else None


def get_login_timeout_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                               "MaxIdleTime")
    return (val == 300000) if val is not None else None


def get_two_factor_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                               "scforceoption")
    return (val == 1) if val is not None else None


def get_biometric_access_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Policies\Microsoft\Biometrics",
                               "Enabled")
    return (val == 1) if val is not None else None


def get_backup_schedule_real_state():
    script = 'Get-ScheduledTask -TaskName "CyberAuditDataBackup" -ErrorAction SilentlyContinue'
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0 or not result.stdout.strip():
        return False
    return True


def get_logon_audit_real_state():
    script = 'auditpol /get /category:"Logon/Logoff"'
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    out_lower = result.stdout.lower()
    if "success" in out_lower or "failure" in out_lower:
        return True
    if "no auditing" in out_lower:
        return False
    return None


def get_security_retention_real_state():
    script = "wevtutil gl Security"
    result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if "retention:" in line:
            return "true" in line.lower()
    return None


def get_win_password_real_state():
    try:
        username = getpass.getuser()
        script = f"(Get-LocalUser -Name '{username}').PasswordRequired"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().lower() == "true"
        return None
    except Exception:
        return None


def get_welcome_screen_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
                               "NoLockScreen")
    return (val != 1)


def get_lan_cards_count_real_state():
    try:
        script = "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).Count"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(result.stdout.strip()) > 0
        return None
    except Exception:
        return None


def get_os_activation_real_state():
    try:
        script = "(Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object {$_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' -and $_.LicenseStatus -eq 1} | Measure-Object).Count"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(result.stdout.strip()) > 0
        return None
    except Exception:
        return None


def get_malware_scan_real_state():
    try:
        script = "(Get-MpThreat | Measure-Object).Count"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(result.stdout.strip()) == 0
        return None
    except Exception:
        return None


def get_non_adn_connections_real_state():
    try:
        script = "(Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notlike '10.*' -and $_.RemoteAddress -notlike '192.168.*' -and $_.RemoteAddress -notlike '172.1[6-9].*' -and $_.RemoteAddress -notlike '172.2[0-9].*' -and $_.RemoteAddress -notlike '172.3[0-1].*' -and $_.RemoteAddress -notlike '127.0.0.1' -and $_.RemoteAddress -notlike '::1'} | Measure-Object).Count"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(result.stdout.strip()) == 0
        return None
    except Exception:
        return None


def get_unwanted_sw_real_state():
    try:
        script = "(Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {$_.DisplayName -like '*torrent*' -or $_.DisplayName -like '*AnyDesk*' -or $_.DisplayName -like '*TeamViewer*' -or $_.DisplayName -like '*CCleaner*'} | Measure-Object).Count"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(result.stdout.strip()) == 0
        return None
    except Exception:
        return None


def get_domain_joined_real_state():
    try:
        script = "(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().lower() == "true"
        return None
    except Exception:
        return None


def get_sccm_installed_real_state():
    try:
        script = "(Get-Service -Name CcmExec -ErrorAction SilentlyContinue).Status"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        return result.returncode == 0 and result.stdout.strip() != ""
    except Exception:
        return None


def get_user_accounts_count_real_state():
    try:
        script = "(Get-LocalUser).Count"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(result.stdout.strip()) <= 5
        return None
    except Exception:
        return None


def get_admin_daily_work_real_state():
    state = get_admin_rights_real_state()
    if state is None:
        return None
    return not state


def get_bios_updated_real_state():
    try:
        script = "(Get-CimInstance -ClassName Win32_BIOS).ReleaseDate"
        res = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            date_str = res.stdout.strip()
            if len(date_str) >= 4:
                year = int(date_str[:4])
                return year >= 2020
        return None
    except Exception:
        return None


def get_ipv6_disabled_real_state():
    try:
        script = "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            count = int(result.stdout.strip())
            return count == 0
        return None
    except Exception:
        return None


def get_folder_sharing_real_state():
    try:
        script = "(Get-Service -Name LanmanServer).Status"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            status = result.stdout.strip().lower()
            if status == "running":
                share_script = "(Get-SmbShare | Where-Object { -not $_.IsSpecial } | Measure-Object).Count"
                share_result = subprocess.run(["powershell", "-Command", share_script], capture_output=True, text=True, timeout=5)
                if share_result.returncode == 0:
                    return int(share_result.stdout.strip()) > 0
            return False
        return None
    except Exception:
        return None


def get_default_shares_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                               "AutoShareWks")
    return (val != 0)


def get_rename_admin_real_state():
    try:
        script = "(Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Name"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            name = result.stdout.strip()
            return name.lower() != "administrator"
        return None
    except Exception:
        return None


def get_usbstor_devices_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start")
    return (val == 3 or val == 2) if val is not None else None


def get_air_gap_real_state():
    try:
        script = "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue"
        res = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        return not bool(res.stdout.strip())
    except Exception:
        return None


def get_classified_data_real_state():
    try:
        user_profile = os.getenv("USERPROFILE") or "C:\\Users"
        count = 0
        for folder in ["Desktop", "Documents"]:
            path = os.path.join(user_profile, folder)
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if any(x in file.lower() for x in ["classified", "confidential", "restricted_data"]):
                            count += 1
                        if count > 0:
                            return False
        return True
    except Exception:
        return None


def get_media_files_real_state():
    try:
        user_profile = os.getenv("USERPROFILE") or "C:\\Users"
        count = 0
        for folder in ["Desktop", "Documents"]:
            path = os.path.join(user_profile, folder)
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.lower().endswith((".mp3", ".mp4", ".avi", ".mkv")):
                            count += 1
                            if count > 5:
                                return False
        return True
    except Exception:
        return None


def get_time_sync_real_state():
    try:
        script = "(Get-Service -Name w32time).Status"
        res = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        is_running = res.stdout.strip().lower() == "running"
        val = read_registry_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "Type")
        is_sync = val in ["NTP", "AllSync"]
        return is_running and is_sync
    except Exception:
        return None


def get_computer_naming_real_state():
    try:
        name = platform.node().upper()
        if name.startswith("DESKTOP-") or name.startswith("LAPTOP-"):
            return False
        return True
    except Exception:
        return None


def get_asset_label_real_state():
    try:
        script = "(Get-CimInstance -ClassName Win32_SystemEnclosure).AssetTag"
        res = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        tag = res.stdout.strip()
        return bool(tag and tag.lower() != "unknown" and "asset" in tag.lower())
    except Exception:
        return None


def get_evidence_collection_real_state():
    try:
        audit_dir = os.path.join(os.getcwd(), "audit_reports")
        if os.path.exists(audit_dir):
            files = os.listdir(audit_dir)
            pdf_files = [f for f in files if f.lower().endswith(".pdf")]
            return len(pdf_files) > 0
        return False
    except Exception:
        return None


def query_service_status(service_name):
    try:
        script = f"(Get-Service -Name {service_name} -ErrorAction SilentlyContinue).Status"
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            status = result.stdout.strip().lower()
            if status == "running":
                return True
            elif status == "stopped":
                return False
        return None
    except Exception:
        return None


def get_remote_assistance_real_state():
    val = read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                               r"System\CurrentControlSet\Control\Terminal Server",
                               "fAllowToGetHelp")
    return (val == 1) if val is not None else None


# ===========================================================================
# STATUS_QUERY_FUNCS: best-effort real-state checks, run only in a
# background thread (StatusCheckWorker). Each function returns True,
# False, or None (= "Unknown / could not verify"). Controls with no entry
# here simply keep their last-known UI state and are clearly labeled
# "Not verified" rather than presented as confirmed.
# ===========================================================================

STATUS_QUERY_FUNCS = {
    "WiFi": get_wifi_real_state,
    "Bluetooth": get_bluetooth_real_state,
    "Hotspot": get_hotspot_real_state,
    "Firewall Enabled": get_firewall_real_state,
    "Admin Rights Control": get_admin_rights_real_state,
    "Antivirus Installed": get_antivirus_real_state,
    "Auto Scan Enabled": get_auto_scan_real_state,
    "Disk Encryption": get_disk_encryption_real_state,
    "Guest Account": lambda: (lambda r: ("yes" in r.lower()) if r else None)(
        subprocess.run(["powershell", "-Command", "net user guest | Select-String 'Account active'"], capture_output=True, text=True).stdout),
    "Ctrl+Alt+Del": lambda: (lambda v: (v == 0) if v is not None else None)(
        read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableCAD")),
    "Display Last User": lambda: (lambda v: (v == 0) if v is not None else None)(
        read_registry_value(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DontDisplayLastUserName")),
    "Secure Boot": get_secure_boot_real_state,
    "Account Lockout": get_account_lockout_real_state,
    "Password Policy": get_password_policy_real_state,
    "Clear Virtual Memory": get_clear_virtual_memory_real_state,
    "Browser Hardening": get_browser_hardening_real_state,
    "Pop-up Blocker": get_popup_blocker_real_state,
    "HTTPS Enforced": get_https_enforced_real_state,
    "Screen Saver Password": get_auto_screen_lock_real_state,
    "Login Timeout": get_login_timeout_real_state,
    "2FA Enabled": get_two_factor_real_state,
    "Biometric Access": get_biometric_access_real_state,
    "Data Backup Schedule": get_backup_schedule_real_state,
    "Audit Policy": get_logon_audit_real_state,
    "Login/Logout Logs": get_logon_audit_real_state,
    "Security Log Retention": get_security_retention_real_state,
    "BIOS Updated": get_bios_updated_real_state,
    "IPv6 Disabled": get_ipv6_disabled_real_state,
    "Folder Sharing": get_folder_sharing_real_state,
    "Default Share": get_default_shares_real_state,
    "Administrator Renamed": get_rename_admin_real_state,
    "Bluetooth Support Service": lambda: query_service_status("bthserv"),
    "Computer Browser": lambda: query_service_status("Browser"),
    "Distributed Link Tracking": lambda: query_service_status("TrkWks"),
    "Fax Service": lambda: query_service_status("Fax"),
    "FTP Publishing": lambda: query_service_status("FTPSVC"),
    "IP Helper": lambda: query_service_status("iphlpsvc"),
    "IIS Admin Service": lambda: query_service_status("IISADMIN"),
    "Remote Registry": lambda: query_service_status("RemoteRegistry"),
    "Routing & Remote Access": lambda: query_service_status("RemoteAccess"),
    "SSDP Discovery": lambda: query_service_status("SSDPSRV"),
    "SNMP Service": lambda: query_service_status("SNMP"),
    "Telnet Service": lambda: query_service_status("TlntSvr"),
    "Remote Assistance": get_remote_assistance_real_state,
    "Win Password": get_win_password_real_state,
    "Welcome Screen": get_welcome_screen_real_state,
    "No of LAN Cards": get_lan_cards_count_real_state,
    "OS Activation Status": get_os_activation_real_state,
    "Malware Scan Check": get_malware_scan_real_state,
    "Non-ADN IP Connections": get_non_adn_connections_real_state,
    "Unwanted Software Scan": get_unwanted_sw_real_state,
    "Domain Joined Status": get_domain_joined_real_state,
    "SCCM Installed": get_sccm_installed_real_state,
    "No of User Account Present": get_user_accounts_count_real_state,
    "Usage of Admin Acct for Daily Wk": get_admin_daily_work_real_state,

    "Netmeeting Remote Desktop": lambda: query_service_status("mnmsrvc"),
    "Remote Auto Connection Manager": lambda: query_service_status("RasAuto"),
    "Remote Desktop": lambda: query_service_status("TermService"),
    "Wireless Service": lambda: query_service_status("WlanSvc"),

    "USB Mass Storage Auditing": get_usbstor_devices_real_state,
    "Air Gap Compliance": get_air_gap_real_state,
    "Classified Data Scan": get_classified_data_real_state,
    "Media Files Compliance": get_media_files_real_state,
    "System Time Sync": get_time_sync_real_state,
    "Computer Naming Compliance": get_computer_naming_real_state,
    "Physical Asset Labeling": get_asset_label_real_state,
    "Audit Evidence Collection": get_evidence_collection_real_state,
}


class StatusCheckWorker(QObject):
    result_ready = pyqtSignal(str, object)   # label, True/False/None
    finished = pyqtSignal()

    def run(self):
        for label, query_fn in STATUS_QUERY_FUNCS.items():
            try:
                value = query_fn()
            except Exception:
                value = None
            self.result_ready.emit(label, value)
        self.finished.emit()


# ===========================================================================
# TOGGLE_EFFECTS -- explanation of what happens when a control is turned
# ON vs OFF. Shown in the confirmation popup AND in the "Understanding
# This Audit" reference panel at the bottom of the dashboard.
# ===========================================================================
 
TOGGLE_EFFECTS = {
    "BIOS Password": {
        "enable": "A BIOS/UEFI password will be required before the computer can boot or before BIOS settings can be changed. Protects against attackers with physical access bypassing the OS entirely.",
        "disable": "The BIOS/UEFI will no longer require a password. Anyone with physical access can change boot settings, boot order, or disable Secure Boot.",
    },
    "Boot Order Lock": {
        "enable": "The boot device order will be locked in BIOS, preventing the system from booting off a USB drive, CD, or network without re-entering BIOS credentials.",
        "disable": "The boot order becomes changeable without restriction, allowing the system to be booted from external/removable media -- a common way to bypass Windows login.",
    },
    "Secure Boot": {
        "enable": "Secure Boot will be enforced, ensuring only digitally signed, trusted bootloaders and OS components can run. Blocks bootkits and unsigned OS tampering.",
        "disable": "Secure Boot will be turned off. The system can boot unsigned or unauthorized OS images and bootloaders, increasing exposure to rootkits/bootkits.",
    },
    "OS Patch Update": {
        "enable": "Opens Windows Update settings so pending OS security patches can be reviewed and installed. Keeps known vulnerabilities patched.",
        "disable": "No update action is taken. Existing OS vulnerabilities remain unpatched until updates are run manually.",
    },
    "Firewall Enabled": {
        "enable": "Windows Defender Firewall will be turned ON for all profiles (Domain/Private/Public), blocking unsolicited inbound network connections.",
        "disable": "Windows Defender Firewall will be turned OFF for all profiles. The machine becomes exposed to unsolicited inbound connections from the network.",
    },
    "Account Lockout": {
        "enable": "Accounts will lock out after 3 failed login attempts, slowing down brute-force password attacks.",
        "disable": "Account lockout threshold is removed (unlimited attempts), making the system vulnerable to brute-force password guessing.",
    },
    "Password Policy": {
        "enable": "Enforces a minimum password length of 8 characters and a maximum password age of 45 days.",
        "disable": "Removes minimum password length and password expiry requirements -- users can set blank or never-expiring passwords.",
    },
    "Guest Account": {
        "enable": "The built-in Guest account will be activated, allowing anonymous/low-privilege logins to this machine.",
        "disable": "The built-in Guest account will be deactivated, removing anonymous local logon capability.",
    },
    "Audit Policy": {
        "enable": "Windows will log both successful and failed logon/logoff events, creating a forensic trail for investigating unauthorized access.",
        "disable": "Logon/logoff auditing will stop. No record of who logged on or off, or of failed login attempts, will be kept.",
    },
    "Ctrl+Alt+Del": {
        "enable": "Users will be required to press Ctrl+Alt+Del before logging in, which protects against fake/spoofed login screens used to steal credentials.",
        "disable": "The Ctrl+Alt+Del requirement before login is removed, slightly increasing risk of credential-stealing fake login screens.",
    },
    "Display Last User": {
        "enable": "The last logged-in username will be hidden on the login screen, making it harder for an attacker to know which account to target.",
        "disable": "The last logged-in username will be shown on the login screen, giving a potential attacker a valid username to target.",
    },
    "Clear Virtual Memory": {
        "enable": "The Windows page file will be wiped on every shutdown, removing any sensitive data that may have been swapped to disk.",
        "disable": "The page file is left intact on shutdown. Residual data (potentially including secrets) may remain recoverable on disk.",
    },
    "Disable Unused Ports": {
        "enable": "(Simulated) Unused network ports are marked as disabled, reducing the attack surface for network-based exploits.",
        "disable": "(Simulated) Unused ports remain open/available, which is a larger attack surface for network-based attacks.",
    },
    "Configure VLANs": {
        "enable": "(Simulated) Network traffic is logically segmented via VLANs, limiting lateral movement if one segment is compromised.",
        "disable": "(Simulated) VLAN segmentation is removed; all devices share one broadcast domain, easing lateral movement for an attacker.",
    },
    "Firewall Rules": {
        "enable": "Opens Windows Firewall with Advanced Security so inbound/outbound rules can be reviewed and tightened.",
        "disable": "No firewall rule changes are made. Existing rules remain as-is.",
    },
    "MAC Filtering": {
        "enable": "(Simulated) Only pre-approved MAC addresses are allowed to connect to the network, blocking unknown devices.",
        "disable": "(Simulated) MAC filtering is removed; any device can attempt to join the network.",
    },
    "Disk Encryption": {
        "enable": "BitLocker will encrypt drive C: using XTS-AES128 with a TPM protector. Data on the disk is unreadable without the recovery key if the drive is removed or stolen.",
        "disable": "BitLocker encryption on drive C: will be removed. Data on the disk becomes readable by anyone with direct disk access (e.g. if the drive is removed).",
    },
    "Admin Rights Control": {
        "enable": "The current user will be added to the local Administrators group, granting full administrative control over this machine.",
        "disable": "The current user will be removed from the local Administrators group, reducing them to standard-user privileges.",
    },
    "Inactive User Removal": {
        "enable": "Local user accounts that have not logged in within 30 days will be permanently deleted. This reduces stale/forgotten accounts that attackers could exploit.",
        "disable": "No inactive accounts will be removed. Stale accounts remain on the system indefinitely.",
    },
    "Antivirus Installed": {
        "enable": "Checks the system for a registered antivirus product via Windows Security Center and reports what's detected.",
        "disable": "Antivirus status will not be checked or displayed.",
    },
    "Auto Scan Enabled": {
        "enable": "Microsoft Defender real-time protection will be turned ON, actively scanning files as they are accessed.",
        "disable": "Microsoft Defender real-time protection will be turned OFF. Malware will not be caught as files are opened/downloaded.",
    },
    "Signature Updates": {
        "enable": "Microsoft Defender virus definition signatures will be updated immediately to recognize the latest known threats.",
        "disable": "No signature update is performed. Existing virus definitions may be out of date.",
    },
    "Browser Hardening": {
        "enable": "Applies group policy to Chrome and Edge: disables Incognito mode, blocks JavaScript by default, and blocks pop-ups. Reduces browser-based attack surface.",
        "disable": "Reverts Chrome/Edge policy: Incognito mode is allowed again, JavaScript and pop-ups are allowed by default.",
    },
    "Pop-up Blocker": {
        "enable": "Chrome and Edge will block pop-up windows by default, reducing exposure to malicious pop-up ads and scareware.",
        "disable": "Chrome and Edge will allow pop-up windows by default.",
    },
    "HTTPS Enforced": {
        "enable": "Chrome and Edge will be forced to use HTTPS connections where possible, protecting against unencrypted traffic interception.",
        "disable": "HTTPS enforcement policy is removed; browsers may fall back to unencrypted HTTP connections.",
    },
    "Access Permissions": {
        "enable": "Grants Full Control on C:\\SecureFolder to the 'Everyone' group. NOTE: this is permissive, not restrictive -- review whether this matches your intent.",
        "disable": "Denies Full Control on C:\\SecureFolder to the 'Everyone' group, blocking access for all standard users.",
    },
    "USB Lock": {
        "enable": "USB ports/devices will be disabled at the device level, preventing use of USB drives, keyboards, or other USB peripherals -- protects against data exfiltration via USB.",
        "disable": "USB ports/devices will be re-enabled, allowing USB peripherals and storage devices to function normally.",
    },
    "CD/DVD Access": {
        "enable": "CD/DVD optical drives will be enabled.",
        "disable": "CD/DVD optical drives will be disabled, preventing use of removable optical media.",
    },
    "Screen Saver Password": {
        "enable": "The screen saver will require a password to dismiss and will activate after 5 minutes of inactivity, locking an unattended session.",
        "disable": "Screen saver password protection and the inactivity timeout are both removed; the screen will not auto-lock.",
    },
    "Display Timeout": {
        "enable": "The display will turn off after 5 minutes of inactivity (AC and battery), reducing the time an unattended unlocked screen is visible.",
        "disable": "The display timeout is set to Never -- the screen stays on indefinitely.",
    },
    "Power Saving Mode": {
        "enable": "Switches the active Windows power plan to 'Power saver'.",
        "disable": "Switches the active Windows power plan to 'High performance'.",
    },
    "Login/Logout Logs": {
        "enable": "Windows will log both successful and failed logon/logoff events for later review.",
        "disable": "Logon/logoff event logging is turned off.",
    },
    "Security Log Retention": {
        "enable": "The Security event log will be set to retain old entries rather than overwrite them when full, preserving a longer audit history.",
        "disable": "The Security event log will overwrite old entries as needed once full, shortening the available audit history.",
    },
    "Log File Encryption": {
        "enable": "Encrypts the C:\\AuditLogs directory using Windows EFS, protecting log contents from being read if the disk is accessed directly.",
        "disable": "Decrypts the C:\\AuditLogs directory, removing EFS protection from stored logs.",
    },
    "WiFi": {
        "enable": "The WiFi network adapter will be enabled, allowing wireless network connections.",
        "disable": "The WiFi network adapter will be disabled. The machine will lose wireless connectivity until re-enabled.",
    },
    "Bluetooth": {
        "enable": "Bluetooth radios/devices will be enabled, allowing Bluetooth peripherals and file transfers.",
        "disable": "Bluetooth radios/devices will be disabled, blocking Bluetooth peripherals and file transfers -- reduces a wireless attack vector.",
    },
    "Hotspot": {
        "enable": "A mobile hotspot ('CyberAuditHotspot') will be started, sharing this machine's network connection wirelessly with other devices.",
        "disable": "The mobile hotspot will be stopped; other devices can no longer connect through it.",
    },
    "2FA Enabled": {
        "enable": "Enforces smart-card / two-factor login requirement at the system policy level, requiring a second factor beyond just a password.",
        "disable": "Removes the two-factor / smart-card login requirement; password-only login is sufficient.",
    },
    "Login Timeout": {
        "enable": "Idle Remote Desktop (RDP) sessions will be disconnected after 5 minutes of inactivity.",
        "disable": "Idle RDP sessions will never be automatically disconnected.",
    },
    "Biometric Access": {
        "enable": "Allows Windows Biometric Framework (fingerprint/face) sign-in to be used where hardware supports it.",
        "disable": "Disables biometric sign-in at the policy level; only password/PIN can be used.",
    },
    "Restart": {
        "enable": "The computer will restart immediately. Unsaved work in open applications will be lost.",
        "disable": "No restart will be performed.",
    },
    "Shut Down": {
        "enable": "The computer will shut down immediately. Unsaved work in open applications will be lost.",
        "disable": "No shutdown will be performed.",
    },
    "Refresh": {
        "enable": "Re-reads current system settings status into the dashboard. No system configuration is changed.",
        "disable": "No refresh is performed.",
    },
    "BIOS Card Reader Disabled": {
        "enable": "Disables the card reader interface at the BIOS level. Prevents reading/writing SD cards or other memory cards, blocking unauthorized storage media.",
        "disable": "Enables the card reader interface at the BIOS level, allowing memory cards to be connected.",
    },
    "BIOS Wireless NW Disabled": {
        "enable": "Disables internal wireless network interfaces (WiFi/Bluetooth) at the BIOS level. Hardens the device against wireless network intrusion.",
        "disable": "Enables internal wireless interfaces at the BIOS level, allowing WiFi and Bluetooth connections.",
    },
    "BIOS Multiple NW Card Disabled": {
        "enable": "Disables secondary or multiple network cards at the BIOS level, preventing dual-homing security policy violations.",
        "disable": "Enables multiple network interfaces at the BIOS level, permitting multiple active network connections.",
    },
    "BIOS Multiple Booting Disabled": {
        "enable": "Disables boot options for multiple operating systems or boot drives in BIOS, securing the system against alternative OS booting.",
        "disable": "Enables multiple booting configurations in BIOS, allowing users to choose alternate boot drives or systems.",
    },
    "BIOS Wake on LAN Disabled": {
        "enable": "Disables Wake-on-LAN (WoL) at the BIOS level, preventing the system from being powered on remotely via network packets.",
        "disable": "Enables Wake-on-LAN in BIOS, allowing network packets to power on the machine.",
    },
    "BIOS Chassis Intrusion Enabled": {
        "enable": "Enables chassis intrusion detection in BIOS, alerting if the physical computer case has been opened.",
        "disable": "Disables chassis intrusion detection in BIOS.",
    },
    "BIOS Updated": {
        "enable": "Checks or marks that the BIOS firmware has been updated to the latest vendor release to patch security vulnerabilities.",
        "disable": "Skips BIOS update verification.",
    },
    "IPv6 Disabled": {
        "enable": "Disables IPv6 on all network adapters, preventing potential IPv6-specific spoofing, tunneling, and scanning attacks.",
        "disable": "Enables IPv6 on all network adapters, allowing standard dual-stack network traffic.",
    },
    "Folder Sharing": {
        "enable": "Enables folder and file sharing on the system by starting the Server service (lanmanserver).",
        "disable": "Disables all custom folder sharing and stops/disables the Server service to secure local files.",
    },
    "Default Share": {
        "enable": "Enables administrative default shares (C$, ADMIN$), allowing remote administrators to access drives directly.",
        "disable": "Disables default administrative shares (C$, ADMIN$) in the registry, blocking direct administrative file access.",
    },
    "Administrator Renamed": {
        "enable": "Renames the default built-in 'Administrator' account to 'SecAdmin' to protect against automated username brute-force attacks.",
        "disable": "Renames the built-in administrator account back to the default 'Administrator' name.",
    },
    "Bluetooth Support Service": {
        "enable": "Starts and enables the Bluetooth Support Service, allowing wireless Bluetooth connections.",
        "disable": "Stops and disables the Bluetooth Support Service, blocking Bluetooth device connections for security.",
    },
    "Computer Browser": {
        "enable": "Starts and enables the Computer Browser service to maintain an active list of computers on the local network.",
        "disable": "Stops and disables the Computer Browser service, preventing network computer name broadcasting.",
    },
    "Distributed Link Tracking": {
        "enable": "Starts and enables the Distributed Link Tracking Client service to maintain links between NTFS files across computers.",
        "disable": "Stops and disables the Distributed Link Tracking Client service, saving system resources and closing potential vectors.",
    },
    "Fax Service": {
        "enable": "Starts and enables the Fax Service, allowing the computer to send and receive faxes.",
        "disable": "Stops and disables the Fax Service, reducing the attack surface by shutting down unused faxing capabilities.",
    },
    "FTP Publishing": {
        "enable": "Starts and enables the IIS FTP Publishing service, allowing FTP file transfers.",
        "disable": "Stops and disables the FTP Publishing service, blocking unencrypted FTP network access.",
    },
    "IP Helper": {
        "enable": "Starts and enables the IP Helper service, providing IPv6 connectivity over IPv4 networks.",
        "disable": "Stops and disables the IP Helper service, disabling IPv6 transition/tunneling mechanisms.",
    },
    "IIS Admin Service": {
        "enable": "Starts and enables the IIS Admin Service, allowing local IIS web server configuration.",
        "disable": "Stops and disables the IIS Admin Service, preventing administrative access to local web server instances.",
    },
    "Remote Registry": {
        "enable": "Starts and enables the Remote Registry service, allowing remote users to modify registry settings on this computer.",
        "disable": "Stops and disables the Remote Registry service, blocking remote users from viewing or changing local registry keys.",
    },
    "Routing & Remote Access": {
        "enable": "Starts and enables the Routing and Remote Access service, providing dial-up and VPN routing services.",
        "disable": "Stops and disables the Routing and Remote Access service, preventing unauthorized routing or incoming VPN connections.",
    },
    "SSDP Discovery": {
        "enable": "Starts and enables the SSDP Discovery service, discovering UPnP devices on the network.",
        "disable": "Stops and disables the SSDP Discovery service, blocking UPnP discovery to prevent device-discovery exploitation.",
    },
    "SNMP Service": {
        "enable": "Starts and enables the Simple Network Management Protocol (SNMP) service for network monitoring.",
        "disable": "Stops and disables the SNMP service, mitigating risks associated with insecure SNMP credentials.",
    },
    "Telnet Service": {
        "enable": "Starts and enables the Telnet service, allowing remote command-line login.",
        "disable": "Stops and disables the Telnet service, preventing unencrypted remote command execution.",
    },
    "Remote Assistance": {
        "enable": "Enables Windows Remote Assistance, allowing remote users to invite help and connect to this PC.",
        "disable": "Disables Windows Remote Assistance, preventing remote desktop support sessions to protect user sessions.",
    },
    "Win Password": {
        "enable": "Enforces that the current Windows user account must require a password to log on. Prevents blank password security bypasses.",
        "disable": "Removes the password requirement for the current user, potentially allowing login without a password.",
    },
    "Welcome Screen": {
        "enable": "Enables the Windows welcome and lock screens, showing personalized backgrounds and user credentials options on startup.",
        "disable": "Disables the lock/welcome screen, bypassing the initial welcome image screen directly to the credential prompt.",
    },
    "No of LAN Cards": {
        "enable": "Opens Network Connections panel to manage active network adapters.",
        "disable": "No action taken.",
    },
    "OS Activation Status": {
        "enable": "Opens Windows Activation Settings so the user can verify or activate their operating system.",
        "disable": "No action taken.",
    },
    "Malware Scan Check": {
        "enable": "Triggers a quick malware scan via Microsoft Defender Antivirus in the background.",
        "disable": "No action taken.",
    },
    "Non-ADN IP Connections": {
        "enable": "Opens Resource Monitor to audit established TCP connections to external IP addresses.",
        "disable": "No action taken.",
    },
    "Unwanted Software Scan": {
        "enable": "Opens Programs & Features control panel to inspect and uninstall blacklisted or unwanted applications.",
        "disable": "No action taken.",
    },
    "Domain Joined Status": {
        "enable": "Opens System Properties to verify if the computer is joined to an Active Directory domain.",
        "disable": "No action taken.",
    },
    "SCCM Installed": {
        "enable": "(Simulated) Verifies SMS Agent Host presence to ensure configuration management compliance.",
        "disable": "(Simulated) Disables SCCM verification.",
    },
    "No of User Account Present": {
        "enable": "Opens Local Users and Groups console to audit and delete unnecessary or unauthorized local accounts.",
        "disable": "No action taken.",
    },
    "Usage of Admin Acct for Daily Wk": {
        "enable": "Removes the current user from the local Administrators group, enforcing standard user compliance for daily operations.",
        "disable": "Adds the current user to the local Administrators group, giving full system control (insecure for daily tasks).",
    },
    "Netmeeting Remote Desktop": {
        "enable": "Starts and enables the Netmeeting Remote Desktop service, allowing remote desktop sharing.",
        "disable": "Stops and disables the Netmeeting Remote Desktop service to prevent unauthorized remote sessions.",
    },
    "Remote Auto Connection Manager": {
        "enable": "Starts and enables the Remote Auto Connection Manager service to automatically connect to remote networks.",
        "disable": "Stops and disables the Remote Auto Connection Manager service to secure network connections.",
    },
    "Remote Desktop": {
        "enable": "Starts and enables the Remote Desktop service (TermService), allowing incoming RDP connections.",
        "disable": "Stops and disables the Remote Desktop service to block all incoming Remote Desktop connections.",
    },
    "Wireless Service": {
        "enable": "Starts and enables the Wireless Lan service (WlanSvc), enabling WiFi configuration and connection.",
        "disable": "Stops and disables the Wireless Lan service, disabling wireless networks at the service level.",
    },
    "USB Mass Storage Auditing": {
        "enable": "Enables the USB Mass Storage driver, allowing standard USB drives to mount and write logs.",
        "disable": "Disables the USB Mass Storage driver registry startup, blocking any external USB storage devices.",
    },
    "Air Gap Compliance": {
        "enable": "Disables all active network adapters to isolate the system from external network entry points.",
        "disable": "Enables network adapters, restoring network connectivity.",
    },
    "Classified Data Scan": {
        "enable": "Scans Desktop and Documents folders for keywords like CLASSIFIED or SECRET to detect unprotected files.",
        "disable": "Skips the metadata scan for classified documents.",
    },
    "Media Files Compliance": {
        "enable": "Audits user folders to locate unauthorized media files (mp3, mp4, avi, etc.) which violate data policy.",
        "disable": "Skips the media file storage compliance scan.",
    },
    "System Time Sync": {
        "enable": "Enforces time synchronization with NTP servers by starting the Windows Time service.",
        "disable": "Stops time synchronization, allowing local clock drift.",
    },
    "Computer Naming Compliance": {
        "enable": "Verifies that the computer name does not use generic default prefixes like LAPTOP- or DESKTOP-.",
        "disable": "Skips computer name convention checks.",
    },
    "Physical Asset Labeling": {
        "enable": "Verifies that a valid corporate asset tag is registered in the SMBIOS enclosure properties.",
        "disable": "Skips bios asset tag checks.",
    },
    "Audit Evidence Collection": {
        "enable": "Verifies that system security audit log reports have been successfully collected and archived.",
        "disable": "Skips the collection status audit.",
    },
}
 
 
def get_effect_text(label, enable):
    entry = TOGGLE_EFFECTS.get(label)
    if not entry:
        return "This will change a system setting. No further details are available."
    return entry["enable"] if enable else entry["disable"]
 
 
# ===========================================================================
# Icons -- simple Unicode glyphs (render natively everywhere, no asset
# files needed -- keeps this a single-file app).
# ===========================================================================
 
SECTION_ICONS = {
    "BIOS Hardening": "\U0001F510",          # locked with key
    "OS Security": "\U0001F4BB",             # laptop
    "Security Policy": "\U0001F4DC",         # scroll
    "Network Security": "\U0001F310",        # globe
    "Data Protection": "\U0001F6E1",         # shield
    "User Account Management": "\U0001F465",  # people
    "Antivirus & Malware": "\U0001F9A0",     # microbe
    "Web Security": "\U0001F310",            # globe (browser-ish)
    "File & Folder Access": "\U0001F4C1",    # folder
    "External Devices": "\U0001F50C",        # plug
    "Display & Power Settings": "\U0001F4A1",  # bulb
    "Audit Trails": "\U0001F4CB",            # clipboard
    "Wireless Configuration": "\U0001F4F6",  # signal bars
    "Authentication": "\U0001F511",          # key
    "Windows Services": "\U0001F6E0",        # hammer & wrench
    "System Power": "\U000023FB",            # power symbol
    "Compliance & Evidence": "\U0001F5C2",   # card index divider
    "Understanding This Audit": "\U0001F4D8",  # blue book
}
 
TOGGLE_ICONS = {
    "BIOS Password": "\U0001F511", "Boot Order Lock": "\U0001F512", "Secure Boot": "\U0001F6E1",
    "OS Patch Update": "\U0001F501", "Firewall Enabled": "\U0001F525", "Account Lockout": "\U0001F512",
    "Password Policy": "\U0001F5DD", "Guest Account": "\U0001F464", "Audit Policy": "\U0001F4CB",
    "Ctrl+Alt+Del": "\u2328", "Display Last User": "\U0001F464", "Clear Virtual Memory": "\U0001F9F9",
    "Disable Unused Ports": "\U0001F50C", "Configure VLANs": "\U0001F310", "Firewall Rules": "\U0001F525",
    "MAC Filtering": "\U0001F4F6", "Disk Encryption": "\U0001F4BE", "Admin Rights Control": "\U0001F451",
    "Inactive User Removal": "\U0001F5D1", "Antivirus Installed": "\U0001F9A0", "Auto Scan Enabled": "\U0001F50D",
    "Signature Updates": "\u2B06", "Browser Hardening": "\U0001F310", "Pop-up Blocker": "\U0001F6AB",
    "HTTPS Enforced": "\U0001F512", "Access Permissions": "\U0001F4C1", "USB Lock": "\U0001F50C",
    "CD/DVD Access": "\U0001F4BF", "Screen Saver Password": "\U0001F512", "Display Timeout": "\U0001F4A1",
    "Power Saving Mode": "\U0001F50B", "Login/Logout Logs": "\U0001F4CB", "Security Log Retention": "\U0001F5C3",
    "Log File Encryption": "\U0001F512", "WiFi": "\U0001F4F6", "Bluetooth": "\U0001F537",
    "Hotspot": "\U0001F4F1", "2FA Enabled": "\U0001F510", "Login Timeout": "\u23F1",
    "Biometric Access": "\U0001F446", "Restart": "\U0001F504", "Shut Down": "\u23FB", "Refresh": "\U0001F501",
    "BIOS Card Reader Disabled": "\U0001F4B3", "BIOS Wireless NW Disabled": "\U0001F4F6",
    "BIOS Multiple NW Card Disabled": "\U0001F5A5", "BIOS Multiple Booting Disabled": "\U0001F4BB",
    "BIOS Wake on LAN Disabled": "\U0001F50C", "BIOS Chassis Intrusion Enabled": "\U0001F6A8",
    "BIOS Updated": "\U0001F501", "IPv6 Disabled": "\U0001F310", "Folder Sharing": "\U0001F4C1",
    "Default Share": "\U0001F4C2", "Administrator Renamed": "\U0001F464",
    "Bluetooth Support Service": "\U0001F537", "Computer Browser": "\U0001F4BB",
    "Distributed Link Tracking": "\U0001F517", "Fax Service": "\U0001F4E0",
    "FTP Publishing": "\U0001F4E4", "IP Helper": "\U0001F4E6",
    "IIS Admin Service": "\U0001F4BB", "Remote Registry": "\U0001F512",
    "Routing & Remote Access": "\U0001F309", "SSDP Discovery": "\U0001F50D",
    "SNMP Service": "\U0001F4E7", "Telnet Service": "\U0001F4BB",
    "Remote Assistance": "\U0001F91D",
    "Win Password": "\U0001F511", "Welcome Screen": "\U0001F5BC",
    "No of LAN Cards": "\U0001F5A5", "OS Activation Status": "\u2705",
    "Malware Scan Check": "\U0001F6E1", "Non-ADN IP Connections": "\U0001F310",
    "Unwanted Software Scan": "\U0001F5D1", "Domain Joined Status": "\U0001F3F0",
    "SCCM Installed": "\U0001F4E6", "No of User Account Present": "\U0001F465",
    "Usage of Admin Acct for Daily Wk": "\U0001F464",
    "Netmeeting Remote Desktop": "\u26F0",
    "Remote Auto Connection Manager": "\u26F2",
    "Remote Desktop": "\U0001F4BB",
    "Wireless Service": "\U0001F4F6",
    "USB Mass Storage Auditing": "\U0001F4BE",
    "Air Gap Compliance": "\u26D4",
    "Classified Data Scan": "\U0001F50D",
    "Media Files Compliance": "\U0001F3B5",
    "System Time Sync": "\u23F0",
    "Computer Naming Compliance": "\U0001F4AC",
    "Physical Asset Labeling": "\U0001F3F7",
    "Audit Evidence Collection": "\U0001F4C2",
}
 


# ===========================================================================
# Theming
# ===========================================================================

LIGHT_THEME = """
QWidget { background-color: #f4f6f9; color: #1b1f24; font-family: 'Segoe UI'; }
QGroupBox {
    font-size: 14px; font-weight: 600; color: #0078d7;
    border: 1px solid #d7dce3; border-radius: 8px; margin-top: 14px; padding-top: 10px;
    background-color: #ffffff;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QListWidget {
    background-color: #1f2733; color: #e7ebf0; font-size: 14px; border: none; padding-top: 6px;
}
QListWidget::item { padding: 10px 14px; border-radius: 0px; }
QListWidget::item:selected { background-color: #0078d7; color: white; }
QListWidget::item:hover { background-color: #2c3a4d; }
QTextEdit { background-color: #ffffff; border: 1px solid #d7dce3; border-radius: 6px; }
QPushButton {
    background-color: #e9edf2; color: #1b1f24; border: 1px solid #d7dce3;
    border-radius: 6px; padding: 6px 12px;
}
QPushButton:hover { background-color: #dde3ea; }
QComboBox { background-color: #ffffff; border: 1px solid #d7dce3; border-radius: 6px; padding: 4px 8px; }
QFrame#statusRowContainer {
    background-color: #f1f5f9;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
}
QFrame#statusRowContainer QLabel {
    color: #1e293b;
    background: transparent;
    border: none;
}
"""

DARK_THEME = """
QWidget { background-color: #1b1f27; color: #e8ecf1; font-family: 'Segoe UI'; }
QGroupBox {
    font-size: 14px; font-weight: 600; color: #4fa3ff;
    border: 1px solid #323a47; border-radius: 8px; margin-top: 14px; padding-top: 10px;
    background-color: #232834;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QListWidget {
    background-color: #11141a; color: #d6dde6; font-size: 14px; border: none; padding-top: 6px;
}
QListWidget::item { padding: 10px 14px; }
QListWidget::item:selected { background-color: #0078d7; color: white; }
QListWidget::item:hover { background-color: #232b38; }
QTextEdit { background-color: #232834; border: 1px solid #323a47; border-radius: 6px; color: #d6dde6; }
QPushButton {
    background-color: #2b323f; color: #e8ecf1; border: 1px solid #3a4250;
    border-radius: 6px; padding: 6px 12px;
}
QPushButton:hover { background-color: #353d4c; }
QComboBox { background-color: #232834; border: 1px solid #3a4250; border-radius: 6px; padding: 4px 8px; color: #e8ecf1; }
QFrame#statusRowContainer {
    background-color: #1b1f27;
    border: 1px solid #323a47;
    border-radius: 8px;
}
QFrame#statusRowContainer QLabel {
    color: #e8ecf1;
    background: transparent;
    border: none;
}
"""


# ===========================================================================
# Confirmation dialog -- shown before every enable/disable action.
# Displays the effect text and asks the user to confirm or cancel.
# ===========================================================================

class ConfirmActionDialog(QDialog):
    def __init__(self, label, enable, parent=None):
        super().__init__(parent)
        action_word = "Enable" if enable else "Disable"
        self.setWindowTitle(f"{action_word} \u2014 {label}")
        self.setMinimumWidth(440)
        
        dark = is_app_dark()
        if dark:
            self.setStyleSheet("""
                QDialog {
                    background-color: #1b1f27;
                    color: #e8ecf1;
                    font-family: 'Segoe UI';
                }
                QLabel {
                    color: #e8ecf1;
                    background: transparent;
                }
            """)
        else:
            self.setStyleSheet("""
                QDialog {
                    background-color: #ffffff;
                    color: #1b1f24;
                    font-family: 'Segoe UI';
                }
                QLabel {
                    color: #1b1f24;
                    background: transparent;
                }
            """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(12)

        heading = QLabel(f"{action_word} '{label}'?")
        heading.setFont(QFont("Segoe UI", 13, QFont.Bold))
        heading.setWordWrap(True)
        layout.addWidget(heading)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("color: #323a47;" if dark else "color: #d7dce3;")
        layout.addWidget(divider)

        effect_label = QLabel("What will happen:")
        effect_label.setFont(QFont("Segoe UI", 9, QFont.Bold))
        layout.addWidget(effect_label)

        effect_text = QLabel(get_effect_text(label, enable))
        effect_text.setWordWrap(True)
        effect_text.setFont(QFont("Segoe UI", 10))
        layout.addWidget(effect_text)

        if label in DEFAULT_STATE:
            recommended = DEFAULT_STATE[label]
            is_rec = (recommended == enable)
            if is_rec:
                rec_text = "This is recommended."
            else:
                rec_text = "This is not recommended.<br><span style='font-weight: normal; font-style: italic;'>Note: the recommended baseline for this control is the opposite setting.</span>"
            rec_label = QLabel(rec_text)
            rec_label.setWordWrap(True)
            rec_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
            if dark:
                rec_label.setStyleSheet("color: #2ea043;" if is_rec else "color: #ff6b6b;")
            else:
                rec_label.setStyleSheet("color: #1a7a3c;" if is_rec else "color: #c0392b;")
            layout.addWidget(rec_label)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet(
            "background-color: #2b323f; color: #e8ecf1; border: 1px solid #3a4250; border-radius: 6px; padding: 7px 18px;"
            if dark else
            "background-color: #e9edf2; color: #1b1f24; border: 1px solid #d7dce3; border-radius: 6px; padding: 7px 18px;"
        )

        confirm_btn = QPushButton(f"{action_word}")
        confirm_btn.setStyleSheet(
            "background-color: #0078d7; color: white; font-weight: bold; padding: 7px 18px; border: none; border-radius: 6px;"
            if enable else
            "background-color: #c0392b; color: white; font-weight: bold; padding: 7px 18px; border: none; border-radius: 6px;"
        )
        confirm_btn.clicked.connect(self.accept)
        button_row.addWidget(cancel_btn)
        button_row.addWidget(confirm_btn)
        layout.addLayout(button_row)


def confirm_toggle(label, enable, parent=None):
    """Show the confirmation dialog. Returns True if the user confirmed."""
    dialog = ConfirmActionDialog(label, enable, parent)
    return dialog.exec_() == QDialog.Accepted


# ===========================================================================
# Login / password dialogs
# ===========================================================================

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberAudit - Authentication")
        self.setFixedSize(400, 280)
        
        self.setStyleSheet("""
            QDialog {
                background-color: #1b1f27;
                color: #e8ecf1;
                font-family: 'Segoe UI';
            }
            QLabel {
                color: #e8ecf1;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #232834;
                border: 1px solid #3a4250;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e8ecf1;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #0078d7;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton#cancelBtn {
                background-color: #2b323f;
                border: 1px solid #3a4250;
                color: #e8ecf1;
            }
            QPushButton#cancelBtn:hover {
                background-color: #353d4c;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header_layout = QHBoxLayout()
        header_icon = QLabel("\U0001F512")
        header_icon.setFont(QFont("Segoe UI", 24))
        header_layout.addWidget(header_icon)
        
        title_info = QVBoxLayout()
        title_lbl = QLabel("CyberAudit Security Portal")
        title_lbl.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title_lbl.setStyleSheet("color: #4fa3ff;")
        subtitle_lbl = QLabel("SLOG Solutions Pvt. Ltd.")
        subtitle_lbl.setFont(QFont("Segoe UI", 10))
        subtitle_lbl.setStyleSheet("color: #aab3c0;")
        title_info.addWidget(title_lbl)
        title_info.addWidget(subtitle_lbl)
        header_layout.addLayout(title_info)
        header_layout.addStretch(1)
        layout.addLayout(header_layout)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter security password...")
        layout.addWidget(self.password_input)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #ff6b6b; font-size: 11px;")
        layout.addWidget(self.error_label)

        button_layout = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("cancelBtn")
        self.cancel_btn.clicked.connect(self.reject)
        
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.try_login)
        
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.login_btn)
        layout.addLayout(button_layout)

        self.password_input.returnPressed.connect(self.try_login)

    def try_login(self):
        if verify_password(self.password_input.text()):
            self.accept()
        else:
            self.error_label.setText("Incorrect password. Please try again.")
            self.password_input.clear()


class PasswordDialog(QDialog):
    def __init__(self, title, forced=False):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(400, 290)
        if forced:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        self.setStyleSheet("""
            QDialog {
                background-color: #1b1f27;
                color: #e8ecf1;
                font-family: 'Segoe UI';
            }
            QLabel {
                color: #e8ecf1;
                font-size: 12px;
            }
            QLineEdit {
                background-color: #232834;
                border: 1px solid #3a4250;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e8ecf1;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #0078d7;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton#cancelBtn {
                background-color: #2b323f;
                border: 1px solid #3a4250;
                color: #e8ecf1;
            }
            QPushButton#cancelBtn:hover {
                background-color: #353d4c;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        header_lbl = QLabel(title)
        header_lbl.setFont(QFont("Segoe UI", 14, QFont.Bold))
        header_lbl.setStyleSheet("color: #4fa3ff;")
        layout.addWidget(header_lbl)

        if forced:
            notice = QLabel("You're using the default password. Please set a new one to continue.")
            notice.setWordWrap(True)
            notice.setStyleSheet("color: #ff9800; font-size: 11px;")
            layout.addWidget(notice)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("New Password")
        layout.addWidget(self.password_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Confirm Password")
        layout.addWidget(self.confirm_input)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #ff6b6b; font-size: 11px;")
        layout.addWidget(self.error_label)

        button_layout = QHBoxLayout()
        if not forced:
            self.cancel_btn = QPushButton("Cancel")
            self.cancel_btn.setObjectName("cancelBtn")
            self.cancel_btn.clicked.connect(self.reject)
            button_layout.addWidget(self.cancel_btn)

        self.update_btn = QPushButton("Update Password")
        self.update_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.update_btn)
        
        layout.addLayout(button_layout)

    def accept(self):
        new_password = self.password_input.text()
        confirm_password = self.confirm_input.text()
        if not new_password:
            self.error_label.setText("Password cannot be empty.")
            return
        if new_password != confirm_password:
            self.error_label.setText("Passwords do not match.")
            return
        super().accept()

    def get_password(self):
        return self.password_input.text()


# ===========================================================================
# StatusRow: one toggle line, now routed through confirm_toggle() and able
# to be driven programmatically (silent=True) by "Revert All to Default".
# ===========================================================================

class StatusRow(QWidget):
    activity_log = []
    status_stats = {}
    all_rows = []  # registry of every row instance, used by revert-all
    label_index = {}  # label_text -> StatusRow

    def __init__(self, label_text, is_password=False):
        super().__init__()
        self.label_text = label_text

        # Load persisted status, default to baseline, or False
        label_clean = label_text.strip()
        saved_states = load_system_audit_state()
        if label_clean in saved_states:
            self.status = saved_states[label_clean]
        elif label_clean in DEFAULT_STATE:
            self.status = DEFAULT_STATE[label_clean]
        else:
            self.status = False
        StatusRow.status_stats[self.label_text] = self.status

        # Main layout of the StatusRow widget itself
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 4, 0, 4)
        main_layout.setSpacing(0)
        
        container = QFrame()
        container.setObjectName("statusRowContainer")
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(16, 12, 16, 12)
        container_layout.setSpacing(16)
        
        icon = TOGGLE_ICONS.get(label_clean, "\u2699")
        self.label = QLabel(f"{icon}  {label_text}")
        self.label.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.label.setFixedWidth(420)
        container_layout.addWidget(self.label)
        container_layout.addSpacing(40)

        # Set status display (Checking... if queryable, else actual state)
        if label_clean in STATUS_QUERY_FUNCS:
            self.status_label = QLabel("Checking...")
            self.status_label.setStyleSheet("font-weight: bold; color: #7d8a9a;")
        else:
            state_str = "Active" if self.status else "Inactive"
            color_str = "#1a7a3c" if self.status else "#c0392b"
            self.status_label = QLabel(state_str)
            self.status_label.setStyleSheet(f"font-weight: bold; color: {color_str};")
        self.status_label.setFixedWidth(120)
        container_layout.addWidget(self.status_label)
        container_layout.addSpacing(40)

        self.toggle_btn = QPushButton("Toggle")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setChecked(self.status)
        self.toggle_btn.setFixedWidth(110)
        self.toggle_btn.setStyleSheet(
            "QPushButton { border-radius: 12px; padding: 6px 18px; font-weight: bold; background-color: #c9ced6; color: #1b1f24; border: none; }"
            "QPushButton:checked { background-color: #1a7a3c; color: white; }")
        self.toggle_btn.clicked.connect(self.on_toggle_clicked)
        container_layout.addWidget(self.toggle_btn)

        if is_password:
            container_layout.addSpacing(20)
            self.update_btn = QPushButton("Update Password")
            self.update_btn.setStyleSheet("background-color: #0078d7; color: white; border-radius: 6px; padding: 6px 14px; font-weight: bold; border: none;")
            self.update_btn.clicked.connect(self.update_password)
            container_layout.addWidget(self.update_btn)

        container_layout.addStretch(1)

        main_layout.addWidget(container)
        self.setLayout(main_layout)
        StatusRow.all_rows.append(self)
        StatusRow.label_index[label_clean] = self

    def apply_real_state_result(self, value):
        """Called by background status-check worker with the real system value (True/False/None)."""
        if value is None:
            return
        self.status = value
        self.toggle_btn.setChecked(self.status)
        self._refresh_status_label()
        StatusRow.status_stats[self.label_text] = self.status

        # Save to state file
        label_clean = self.label_text.strip()
        saved_states = load_system_audit_state()
        saved_states[label_clean] = self.status
        save_system_audit_state(saved_states)

    # ------------------------------------------------------------------
    def on_toggle_clicked(self):
        """User clicked the toggle button directly -- show confirmation
        before doing anything, and roll the button back if cancelled."""
        intended_state = self.toggle_btn.isChecked()
        label_clean = self.label_text.strip()

        if not confirm_toggle(label_clean, intended_state, self):
            # User cancelled -- restore the button to its prior visual state
            self.toggle_btn.setChecked(not intended_state)
            return

        self.apply_toggle(intended_state)

    def apply_toggle(self, intended_state, silent=False):
        """Actually perform the toggle. If silent=True, skip the confirmation
        dialog (used by Revert All to Default) but still sync the button UI."""
        label_clean = self.label_text.strip()
        self.status = intended_state
        self.toggle_btn.setChecked(self.status)
        self._refresh_status_label()

        success = True
        if label_clean == "WiFi":
            adapters = get_wifi_adapters()
            if adapters:
                success = set_adapter_state(adapters[0], enable=self.status)
            else:
                adapter_name, ok = QInputDialog.getText(
                    self, "WiFi Adapter",
                    "Enter the adapter name for WiFi (e.g., 'Wi-Fi'):\n"
                    "(Run 'netsh interface show interface' in PowerShell to list adapters)"
                )
                success = set_adapter_state(adapter_name, enable=self.status) if (ok and adapter_name) else False
        elif label_clean == "Bluetooth":
            success = toggle_bluetooth(enable=self.status)
        elif label_clean == "Hotspot":
            success = toggle_hotspot(enable=self.status)
        elif label_clean == "Restart":
            dashboard = self.window()
            if hasattr(dashboard, "confirm_power_action") and not dashboard.confirm_power_action("Restart"):
                success = False
            else:
                success = handle_restart()
        elif label_clean == "Shut Down":
            dashboard = self.window()
            if hasattr(dashboard, "confirm_power_action") and not dashboard.confirm_power_action("Shut Down"):
                success = False
            else:
                success = handle_shutdown()
        elif label_clean == "Refresh":
            success = handle_refresh()
        elif label_clean in SECURITY_POLICY_ACTIONS:
            try:
                result = SECURITY_POLICY_ACTIONS[label_clean](self.status)
                success = result if result is not None else True
            except Exception as e:
                if not silent:
                    QMessageBox.critical(self, "Security Policy Error", f"Failed to apply policy '{label_clean}': {e}")
                success = False

        if not success:
            self._revert_ui(not intended_state)
            return False

        # Save to state file
        saved_states = load_system_audit_state()
        saved_states[label_clean] = self.status
        save_system_audit_state(saved_states)

        log_activity(f"{self.label_text} set to {'Active' if self.status else 'Inactive'}")
        StatusRow.status_stats[self.label_text] = self.status
        return True

    def _refresh_status_label(self):
        state = "Active" if self.status else "Inactive"
        color = "#1a7a3c" if self.status else "#c0392b"
        self.status_label.setText(state)
        self.status_label.setStyleSheet(f"font-weight: bold; color: {color};")

    def _revert_ui(self, reverted_status):
        self.status = reverted_status
        self.toggle_btn.setChecked(self.status)
        self._refresh_status_label()

    def update_password(self):
        dialog = PasswordDialog("Update Password")
        if dialog.exec_() == QDialog.Accepted:
            new_password = dialog.get_password()
            if new_password:
                set_new_password(new_password)
                self.status_label.setText("Password Updated")
                self.status_label.setStyleSheet("font-weight: bold; color: darkgreen;")
                log_activity(f"Password updated for {self.label_text}")


class SectionBox(QGroupBox):
    def __init__(self, title, items, password_items=None):
        icon = SECTION_ICONS.get(title, "")
        super().__init__(f"{icon}  {title}" if icon else title)
        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(12, 16, 12, 16)
        password_items = password_items or set()
        for item in items:
            layout.addWidget(StatusRow(item, is_password=(item in password_items)))
        self.setLayout(layout)


def get_system_info():
    return (
        f"System: {platform.system()} | Node: {platform.node()} | "
        f"Release: {platform.release()} | Version: {platform.version()} | "
        f"Machine: {platform.machine()} | Processor: {platform.processor()}"
    )


def build_reference_html(sections, dark=False):
    """Builds the full reference document shown in the bottom panel and
    used as a help screen."""
    if dark:
        text_color = "#e8ecf1"
        muted_color = "#aab3c0"
        border_color = "#3a4250"
        head_bg = "#2a3140"
        body_bg = "#232834"
    else:
        text_color = "#1b1f24"
        muted_color = "#5a6472"
        border_color = "#d7dce3"
        head_bg = "#eef2f7"
        body_bg = "#ffffff"

    parts = []
    parts.append(f"""
    <div style="color:{text_color}; background-color:{body_bg};">
    <h2 style="margin-bottom:4px; color:{text_color};">\U0001F4D8 Understanding This Audit</h2>
    <p style="color:{muted_color};">
        This page explains every control on the dashboard in plain language:
        what it does, what happens when you turn it ON vs OFF, what this
        tool recommends as the safe default, and what each status word means.
    </p>
    <h3 style="color:{text_color};">What the status words mean</h3>
    <table cellspacing="0" cellpadding="6" width="100%" style="border-collapse:collapse;">
      <tr style="background:{head_bg};">
        <th align="left" style="border:1px solid {border_color}; color:{text_color};">Status</th>
        <th align="left" style="border:1px solid {border_color}; color:{text_color};">Meaning</th>
      </tr>
      <tr><td style="border:1px solid {border_color}; color:#2ea043; font-weight:bold;">Active</td>
          <td style="border:1px solid {border_color}; color:{text_color};">The control is currently ON.</td></tr>
      <tr><td style="border:1px solid {border_color}; color:#e0564a; font-weight:bold;">Inactive</td>
          <td style="border:1px solid {border_color}; color:{text_color};">The control is currently OFF.</td></tr>
      <tr><td style="border:1px solid {border_color}; color:#3393e8; font-weight:bold;">Working...</td>
          <td style="border:1px solid {border_color}; color:{text_color};">A change is being applied right now in the background. The window stays responsive while this runs.</td></tr>
      <tr><td style="border:1px solid {border_color}; color:{muted_color}; font-weight:bold;">Checking...</td>
          <td style="border:1px solid {border_color}; color:{text_color};">The app is asking Windows for the real current state. This only happens briefly after opening the app.</td></tr>
      <tr><td style="border:1px solid {border_color}; color:#d4a017; font-weight:bold;">Unknown</td>
          <td style="border:1px solid {border_color}; color:{text_color};">Windows could not confirm the real state (e.g. the hardware isn't present, or the check needs admin rights). Verify this one manually if it matters.</td></tr>
      <tr><td style="border:1px solid {border_color}; color:{muted_color}; font-weight:bold;">Not verified</td>
          <td style="border:1px solid {border_color}; color:{text_color};">There is no automatic way to read this control's real state from Windows. The label shown reflects only what was last set inside this app -- it is not a live read of the system.</td></tr>
    </table>
    <h3 style="margin-top:18px; color:{text_color};">Controls, by section</h3>
    """)

    for section, items in sections.items():
        parts.append(f'<h4 style="color:#3393e8; margin-top:16px;">{SECTION_ICONS.get(section,"")} {section}</h4>')
        parts.append(f'<table cellspacing="0" cellpadding="6" width="100%" style="border-collapse:collapse; margin-bottom:6px;">')
        parts.append(f'<tr style="background:{head_bg};">'
                      f'<th align="left" style="border:1px solid {border_color}; width:16%; color:{text_color};">Control</th>'
                      f'<th align="left" style="border:1px solid {border_color}; width:30%; color:{text_color};">When Enabled</th>'
                      f'<th align="left" style="border:1px solid {border_color}; width:30%; color:{text_color};">When Disabled</th>'
                      f'<th align="left" style="border:1px solid {border_color}; width:12%; color:{text_color};">Recommended Default</th>'
                      f'<th align="left" style="border:1px solid {border_color}; width:12%; color:{text_color};">Real-time Status Check</th></tr>')
        for item in items:
            effect = TOGGLE_EFFECTS.get(item, {})
            enabled_text = effect.get("enable", "\u2014")
            disabled_text = effect.get("disable", "\u2014")
            if item in DEFAULT_STATE:
                default_text = "ON" if DEFAULT_STATE[item] else "OFF"
                default_color = "#2ea043" if DEFAULT_STATE[item] else "#e0564a"
            else:
                default_text, default_color = "N/A", muted_color
            verifiable = "Yes" if item in STATUS_QUERY_FUNCS else "Not verified"
            verify_color = "#2ea043" if item in STATUS_QUERY_FUNCS else muted_color
            icon = TOGGLE_ICONS.get(item, "\u2699")
            parts.append(
                f'<tr>'
                f'<td style="border:1px solid {border_color}; font-weight:bold; color:{text_color};">{icon} {item}</td>'
                f'<td style="border:1px solid {border_color}; color:{text_color};">{enabled_text}</td>'
                f'<td style="border:1px solid {border_color}; color:{text_color};">{disabled_text}</td>'
                f'<td style="border:1px solid {border_color}; color:{default_color}; font-weight:bold;">{default_text}</td>'
                f'<td style="border:1px solid {border_color}; color:{verify_color};">{verifiable}</td>'
                f'</tr>'
            )
        parts.append('</table>')

    parts.append(f"""
    <h3 style="margin-top:18px; color:{text_color};">A note on "Recommended Default"</h3>
    <p style="color:{muted_color};">
        These defaults follow common hardening guidance: protective controls
        (firewall, encryption, antivirus, lockouts) default ON, and
        risk-introducing controls (guest account, USB lock off, admin rights)
        default OFF. Your organization's actual policy may differ -- the
        "Revert All to Default" button uses exactly this list, so review it
        before relying on that button in a real environment.
    </p>
    </div>
    """)
    return "".join(parts)


# ===========================================================================
# PDF report -- formatted with a header band, section table, and footer.
# ===========================================================================

class AuditReportPDF(FPDF):
    def header(self):
        self.set_fill_color(0, 70, 130)
        self.rect(0, 0, 210, 26, "F")
        self.set_xy(10, 6)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 8, "External System Security Audit", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(10)
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, "SLOG Solutions Pvt. Ltd.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_y(30)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")
        self.set_text_color(0, 0, 0)

    def section_title(self, text):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(230, 236, 245)
        self.set_text_color(0, 70, 130)
        self.cell(0, 9, f"  {text}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.set_text_color(0, 0, 0)
        self.set_x(self.l_margin)
        self.ln(2)

    def kv_row(self, key, value, key_w=55):
        self.set_x(self.l_margin)
        start_x = self.get_x()
        start_y = self.get_y()
        self.set_font("Helvetica", "B", 9.5)
        self.cell(key_w, 6, key)
        self.set_font("Helvetica", "", 9.5)
        self.set_xy(start_x + key_w, start_y)
        value_width = self.w - self.r_margin - (start_x + key_w)
        self.multi_cell(value_width, 6, value)
        self.set_x(self.l_margin)


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self._initial_check_done = False
        self._session_initial_states = {}
        self.setWindowTitle("External System Security Audit - SLOG Solutions Pvt. Ltd.")
        self.setMinimumSize(1150, 920)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ---- Header band ----
        header = QWidget()
        header.setStyleSheet("background-color: #003e6b;")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 14, 20, 14)
        title_label = QLabel("\U0001F6E1  External System Security Audit")
        title_label.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title_label.setStyleSheet("color: white;")
        title_label.setAlignment(Qt.AlignCenter)
        subtitle_label = QLabel("SLOG Solutions Pvt. Ltd.")
        subtitle_label.setFont(QFont("Segoe UI", 11))
        subtitle_label.setStyleSheet("color: #cfe3f7;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        main_layout.addWidget(header)

        self.system_info_label = QLabel(get_system_info())
        self.system_info_label.setAlignment(Qt.AlignCenter)
        self.system_info_label.setStyleSheet("font-size: 10pt; padding: 8px;")
        main_layout.addWidget(self.system_info_label)

        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(12, 0, 12, 0)

        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(280)

        self.sections = {
            "BIOS Hardening": [
                "BIOS Password", "Boot Order Lock", "Secure Boot",
                "BIOS Card Reader Disabled", "BIOS Wireless NW Disabled",
                "BIOS Multiple NW Card Disabled", "BIOS Multiple Booting Disabled",
                "BIOS Wake on LAN Disabled", "BIOS Chassis Intrusion Enabled", "BIOS Updated"
            ],
            "OS Security": ["OS Patch Update", "OS Activation Status", "SCCM Installed", "Unwanted Software Scan"],
            "Security Policy": [
                "Password Policy", "Account Lockout", "Audit Policy", "No of User Account Present",
                "Guest Account", "Administrator Renamed", "Ctrl+Alt+Del", "Display Last User",
                "Clear Virtual Memory", "Usage of Admin Acct for Daily Wk", "Welcome Screen"
            ],
            "Network Security": ["Firewall Enabled", "Disable Unused Ports", "Configure VLANs", "Firewall Rules", "MAC Filtering", "IPv6 Disabled", "No of LAN Cards", "Non-ADN IP Connections"],
            "Data Protection": ["Disk Encryption"],
            "User Account Management": ["Admin Rights Control", "Inactive User Removal"],
            "Antivirus & Malware": ["Antivirus Installed", "Auto Scan Enabled", "Signature Updates", "Malware Scan Check"],
            "Web Security": ["Browser Hardening", "Pop-up Blocker", "HTTPS Enforced"],
            "File & Folder Access": ["Access Permissions", "Folder Sharing", "Default Share"],
            "External Devices": ["USB Lock", "CD/DVD Access"],
            "Display & Power Settings": ["Screen Saver Password", "Display Timeout", "Power Saving Mode"],
            "Audit Trails": ["Login/Logout Logs", "Security Log Retention", "Log File Encryption"],
            "Wireless Configuration": ["WiFi", "Bluetooth", "Hotspot"],
            "Authentication": ["2FA Enabled", "Login Timeout", "Biometric Access", "Win Password"],
            "Windows Services": [
                "Bluetooth Support Service", "Computer Browser", "Distributed Link Tracking", "Fax Service",
                "FTP Publishing", "IP Helper", "IIS Admin Service", "Remote Registry",
                "Routing & Remote Access", "SSDP Discovery", "SNMP Service", "Telnet Service", "Remote Assistance",
                "Netmeeting Remote Desktop", "Remote Auto Connection Manager", "Remote Desktop", "Wireless Service"
            ],
            "Compliance & Evidence": [
                "USB Mass Storage Auditing", "Air Gap Compliance", "Classified Data Scan",
                "Media Files Compliance", "System Time Sync", "Computer Naming Compliance",
                "Physical Asset Labeling", "Audit Evidence Collection"
            ],
            "System Power": ["Restart", "Shut Down", "Refresh"],
        }

        self.stack_layout = QStackedLayout()
        for section, items in self.sections.items():
            icon = SECTION_ICONS.get(section, "")
            item_text = f"{icon}  {section}" if icon else section
            self.sidebar.addItem(QListWidgetItem(item_text))
            
            scroll_area = QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setFrameShape(QFrame.NoFrame)
            scroll_area.setStyleSheet("background: transparent; border: none;")
            
            content = QWidget()
            vbox = QVBoxLayout(content)
            vbox.setContentsMargins(10, 10, 10, 10)
            vbox.addWidget(SectionBox(section, items, password_items={"BIOS Password"}))
            vbox.addStretch(1)
            
            scroll_area.setWidget(content)
            self.stack_layout.addWidget(scroll_area)

        # Populate session initial states immediately with loaded values
        self._session_initial_states = {row.label_text.strip(): row.status for row in StatusRow.all_rows}

        # Restore "Understanding This Audit" help tab/panel
        ref_icon = SECTION_ICONS.get("Understanding This Audit", "")
        ref_text = f"{ref_icon}  Understanding This Audit" if ref_icon else "Understanding This Audit"
        self.sidebar.addItem(QListWidgetItem(ref_text))
        self.ref_scroll = QScrollArea()
        self.ref_scroll.setWidgetResizable(True)
        self.reference_widget = QTextEdit()
        self.reference_widget.setReadOnly(True)
        self.ref_scroll.setWidget(self.reference_widget)
        self.stack_layout.addWidget(self.ref_scroll)

        self.sidebar.currentRowChanged.connect(self.stack_layout.setCurrentIndex)

        content_layout.addWidget(self.sidebar)
        stack_widget = QWidget()
        stack_widget.setLayout(self.stack_layout)
        content_layout.addWidget(stack_widget)

        main_layout.addLayout(content_layout)

        bottom_layout = QVBoxLayout()
        bottom_layout.setContentsMargins(12, 8, 12, 8)
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(180)
        bottom_layout.addWidget(self.log_display)

        footer = QHBoxLayout()
        footer.setContentsMargins(12, 10, 12, 12)
        footer.setSpacing(8)

        # Left aligned
        self.theme_toggle_btn = QPushButton("🌙 Dark Mode")
        self.theme_toggle_btn.setMinimumHeight(36)
        self.theme_toggle_btn.setStyleSheet("font-weight: bold; padding: 6px 12px;")
        self.theme_toggle_btn.clicked.connect(self.toggle_theme)
        footer.addWidget(self.theme_toggle_btn)

        self.refresh_status_btn = QPushButton("\u27f3  Refresh Status")
        self.refresh_status_btn.setMinimumHeight(36)
        self.refresh_status_btn.setStyleSheet("background-color: #27ae60; color: white; padding: 6px 12px; font-weight: bold;")
        self.refresh_status_btn.clicked.connect(self.manual_refresh_status)
        footer.addWidget(self.refresh_status_btn)

        self.revert_btn = QPushButton("\u21bb  Revert Session Changes")
        self.revert_btn.setMinimumHeight(36)
        self.revert_btn.setStyleSheet("background-color: #c0392b; color: white; padding: 6px 12px; font-weight: bold;")
        self.revert_btn.clicked.connect(self.revert_to_session_default)
        footer.addWidget(self.revert_btn)

        self.understand_btn = QPushButton("\U0001F4D8  Understand Audit")
        self.understand_btn.setMinimumHeight(36)
        self.understand_btn.setStyleSheet("background-color: #0078d7; color: white; padding: 6px 12px; font-weight: bold;")
        self.understand_btn.clicked.connect(self.switch_to_understand_tab)
        footer.addWidget(self.understand_btn)

        # Middle stretch
        footer.addStretch(1)

        # Right aligned
        self.prev_audits_btn = QPushButton("\U0001F5C3  View Audits")
        self.prev_audits_btn.setMinimumHeight(36)
        self.prev_audits_btn.setStyleSheet("font-weight: bold; padding: 6px 12px;")
        self.prev_audits_btn.clicked.connect(self.open_previous_audits)
        footer.addWidget(self.prev_audits_btn)

        self.refresh_btn = QPushButton("\u21bb  Refresh Logs")
        self.refresh_btn.setMinimumHeight(36)
        self.refresh_btn.setStyleSheet("font-weight: bold; padding: 6px 12px;")
        self.refresh_btn.clicked.connect(self.refresh_log)
        footer.addWidget(self.refresh_btn)

        self.change_pwd_btn = QPushButton("\U0001F511  Change Password")
        self.change_pwd_btn.setMinimumHeight(36)
        self.change_pwd_btn.setStyleSheet("background-color: #ff9800; color: white; padding: 6px 12px; font-weight: bold; border-radius: 6px;")
        self.change_pwd_btn.clicked.connect(self.open_change_password)
        footer.addWidget(self.change_pwd_btn)

        save_btn = QPushButton("\U0001F4E5  Save PDF")
        save_btn.setMinimumHeight(36)
        save_btn.setStyleSheet("background-color: #0078d7; color: white; padding: 6px 12px; font-weight: bold;")
        save_btn.clicked.connect(self.save_report)
        footer.addWidget(save_btn)

        bottom_layout.addLayout(footer)
        main_layout.addLayout(bottom_layout)
        self.sidebar.setCurrentRow(0)
        self.refresh_log()
        self.change_theme(0)
        QTimer.singleShot(150, lambda: self.start_status_check(is_initial=True))

    def switch_to_understand_tab(self):
        self.sidebar.setCurrentRow(self.sidebar.count() - 1)

    # ------------------------------------------------------------------
    def revert_to_session_default(self):
        confirm = QMessageBox.question(
            self, "Revert All to Session Default",
            "This will revert all system settings changed during this session back to "
            "their state when the application was opened.\n\n"
            "Each underlying system change will still be applied.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        changed, skipped = 0, 0
        for row in StatusRow.all_rows:
            label_clean = row.label_text.strip()
            if label_clean not in self._session_initial_states:
                skipped += 1
                continue
            target = self._session_initial_states[label_clean]
            if row.status == target:
                continue
            row.apply_toggle(target, silent=True)
            changed += 1

        log_activity(f"Revert to Session Default executed: {changed} control(s) reverted, {skipped} skipped.")
        self.refresh_log()
        QMessageBox.information(
            self, "Revert Complete",
            f"{changed} control(s) were reverted to their initial session state."
        )

    def refresh_log(self):
        self.log_display.setPlainText("\n".join(StatusRow.activity_log[-10:]))

    def open_change_password(self):
        dialog = PasswordDialog("Change App Password")
        if dialog.exec_() == QDialog.Accepted:
            new_password = dialog.get_password()
            set_new_password(new_password)
            QMessageBox.information(self, "Password Changed", "The app password has been updated successfully.")

    def save_report(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Save Report", "audit_report.pdf", "PDF Files (*.pdf)")
        if not filepath:
            return
        if not filepath.lower().endswith(".pdf"):
            filepath += ".pdf"

        pdf = AuditReportPDF()
        pdf.set_auto_page_break(auto=True, margin=18)
        pdf.add_page()

        pdf.section_title("Report Metadata")
        pdf.kv_row("Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        pdf.kv_row("System Info:", self.system_info_label.text())
        pdf.ln(4)

        pdf.section_title("Control Status Summary")
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_fill_color(245, 247, 250)
        col_widths = [70, 30, 90]
        headers = ["Control", "Status", "Section"]
        for w, h in zip(col_widths, headers):
            pdf.cell(w, 7, h, border=1, fill=True)
        pdf.ln()
        pdf.set_font("Helvetica", "", 9)

        label_to_section = {}
        for section, items in self.sections.items():
            for item in items:
                label_to_section[item] = section

        for row in StatusRow.all_rows:
            label = row.label_text.strip()
            status_text = "Active" if row.status else "Inactive"
            pdf.set_x(pdf.l_margin)
            if row.status:
                pdf.set_text_color(20, 120, 60)
            else:
                pdf.set_text_color(180, 50, 40)
            pdf.cell(col_widths[0], 6.5, label, border=1)
            pdf.cell(col_widths[1], 6.5, status_text, border=1)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(col_widths[2], 6.5, label_to_section.get(label, ""), border=1)
            pdf.ln()

        pdf.ln(4)
        pdf.section_title("Recent Activity Log")
        pdf.set_font("Helvetica", "", 9)
        if StatusRow.activity_log:
            for index, entry in enumerate(StatusRow.activity_log[-25:], start=1):
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 6, f"{index}. {entry}")
        else:
            pdf.cell(0, 7, "No activity logs recorded.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(4)
        pdf.section_title("Dashboard Summary")
        enabled_count = sum(1 for row in StatusRow.all_rows if row.status)
        total_rows = len(StatusRow.all_rows)
        pdf.kv_row("Total controls:", str(total_rows))
        pdf.kv_row("Currently active:", str(enabled_count))
        pdf.kv_row("Currently inactive:", str(total_rows - enabled_count))

        pdf.output(filepath)
        QMessageBox.information(self, "Saved", f"PDF report saved to:\n{filepath}")

    def start_status_check(self, is_initial=False):
        if hasattr(self, '_status_thread') and self._status_thread is not None:
            try:
                if self._status_thread.isRunning():
                    QMessageBox.warning(
                        self,
                        "Scan in Progress",
                        "The application is currently fetching the system status.\n\n"
                        "Please wait for the current scan to complete before refreshing."
                    )
                    return
            except RuntimeError:
                self._status_thread = None

        self._status_thread = QThread()
        self._status_worker = StatusCheckWorker()
        self._status_worker.moveToThread(self._status_thread)
        self._status_thread.started.connect(self._status_worker.run)
        self._status_worker.result_ready.connect(self._on_status_result)
        self._status_worker.finished.connect(self._status_thread.quit)
        self._status_worker.finished.connect(self._status_worker.deleteLater)
        self._status_thread.finished.connect(self._status_thread.deleteLater)
        self._status_thread.finished.connect(lambda: self._clear_status_thread())
        if is_initial:
            self._status_thread.finished.connect(self._mark_initial_check_done)
        self._status_thread.start()

    def _clear_status_thread(self):
        self._status_thread = None

    def _mark_initial_check_done(self):
        self._initial_check_done = True
        log_activity("Initial system status check complete. Session state baseline recorded.")

    def _on_status_result(self, label, value):
        row = StatusRow.label_index.get(label)
        if row is not None:
            row.apply_real_state_result(value)
            if not self._initial_check_done:
                self._session_initial_states[label] = row.status

    def manual_refresh_status(self):
        for row in StatusRow.all_rows:
            label_clean = row.label_text.strip()
            if label_clean in STATUS_QUERY_FUNCS:
                row.status_label.setText("Checking...")
                row.status_label.setStyleSheet("font-weight: bold; color: #7d8a9a;")
        self.start_status_check(is_initial=False)

    def closeEvent(self, event):
        any_changes = False
        for row in StatusRow.all_rows:
            label_clean = row.label_text.strip()
            if label_clean in self._session_initial_states:
                if row.status != self._session_initial_states[label_clean]:
                    any_changes = True
                    break

        if not any_changes:
            if hasattr(self, "_status_thread") and self._status_thread is not None:
                try:
                    if self._status_thread.isRunning():
                        self._status_thread.terminate()
                        self._status_thread.wait()
                except RuntimeError:
                    pass
            event.accept()
            return

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Exit Application")
        msg_box.setText("You have made changes during this session. How would you like to exit?")
        
        save_btn = msg_box.addButton("Close with all changes", QMessageBox.AcceptRole)
        discard_btn = msg_box.addButton("Close without changes", QMessageBox.DestructiveRole)
        cancel_btn = msg_box.addButton("Cancel", QMessageBox.RejectRole)
        
        msg_box.setDefaultButton(save_btn)
        msg_box.exec_()
        
        clicked = msg_box.clickedButton()
        if clicked == save_btn:
            if hasattr(self, "_status_thread") and self._status_thread is not None:
                try:
                    if self._status_thread.isRunning():
                        self._status_thread.terminate()
                        self._status_thread.wait()
                except RuntimeError:
                    pass
            event.accept()
        elif clicked == discard_btn:
            # Show a non-blocking progress pop-up
            revert_msg = QMessageBox(self)
            revert_msg.setWindowTitle("Reverting Changes")
            revert_msg.setText("Reverting session changes. Please wait...")
            revert_msg.setIcon(QMessageBox.Information)
            revert_msg.setStandardButtons(QMessageBox.NoButton)
            revert_msg.show()
            QApplication.processEvents()

            # Revert all changes made during the session
            for row in StatusRow.all_rows:
                label_clean = row.label_text.strip()
                if label_clean in self._session_initial_states:
                    target = self._session_initial_states[label_clean]
                    if row.status != target:
                        row.apply_toggle(target, silent=True)
            
            revert_msg.close()

            if hasattr(self, "_status_thread") and self._status_thread is not None:
                try:
                    if self._status_thread.isRunning():
                        self._status_thread.terminate()
                        self._status_thread.wait()
                except RuntimeError:
                    pass
            event.accept()
        else:
            event.ignore()

    def confirm_power_action(self, action_type):
        any_changes = False
        for row in StatusRow.all_rows:
            label_clean = row.label_text.strip()
            if label_clean in self._session_initial_states:
                if row.status != self._session_initial_states[label_clean]:
                    any_changes = True
                    break

        if not any_changes:
            # Terminate checking thread cleanly before system power event
            if hasattr(self, "_status_thread") and self._status_thread is not None:
                try:
                    if self._status_thread.isRunning():
                        self._status_thread.terminate()
                        self._status_thread.wait()
                except RuntimeError:
                    pass
            return True

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(f"Confirm {action_type}")
        msg_box.setText(f"You have made changes during this session. How would you like to proceed before {action_type.lower()}?")
        
        save_btn = msg_box.addButton(f"Save changes & {action_type}", QMessageBox.AcceptRole)
        discard_btn = msg_box.addButton(f"Discard changes & {action_type}", QMessageBox.DestructiveRole)
        cancel_btn = msg_box.addButton("Cancel", QMessageBox.RejectRole)
        
        msg_box.setDefaultButton(save_btn)
        msg_box.exec_()
        
        clicked = msg_box.clickedButton()
        if clicked == save_btn:
            if hasattr(self, "_status_thread") and self._status_thread is not None:
                try:
                    if self._status_thread.isRunning():
                        self._status_thread.terminate()
                        self._status_thread.wait()
                except RuntimeError:
                    pass
            return True
        elif clicked == discard_btn:
            # Show a non-blocking progress pop-up
            revert_msg = QMessageBox(self)
            revert_msg.setWindowTitle("Reverting Changes")
            revert_msg.setText("Reverting session changes. Please wait...")
            revert_msg.setIcon(QMessageBox.Information)
            revert_msg.setStandardButtons(QMessageBox.NoButton)
            revert_msg.show()
            QApplication.processEvents()

            # Revert all changes made during the session
            for row in StatusRow.all_rows:
                label_clean = row.label_text.strip()
                if label_clean in self._session_initial_states:
                    target = self._session_initial_states[label_clean]
                    if row.status != target:
                        row.apply_toggle(target, silent=True)
            
            revert_msg.close()

            if hasattr(self, "_status_thread") and self._status_thread is not None:
                try:
                    if self._status_thread.isRunning():
                        self._status_thread.terminate()
                        self._status_thread.wait()
                except RuntimeError:
                    pass
            return True
        else:
            return False

    def toggle_theme(self):
        new_theme = 1 if not self._is_dark else 0
        self.change_theme(new_theme)

    def change_theme(self, index):
        self._is_dark = (index == 1)
        if hasattr(self, 'theme_toggle_btn'):
            self.theme_toggle_btn.setText("🌞 Light Mode" if self._is_dark else "🌙 Dark Mode")
        self.setStyleSheet(LIGHT_THEME if not self._is_dark else DARK_THEME)
        if hasattr(self, 'reference_widget'):
            self.reference_widget.setHtml(build_reference_html(self.sections, dark=self._is_dark))

    def open_previous_audits(self):
        audit_dir = os.path.join(os.getcwd(), "audit_reports")
        if not os.path.exists(audit_dir):
            os.makedirs(audit_dir)
        os.startfile(audit_dir)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ensure_password_file()

    login_dialog = LoginDialog()
    if login_dialog.exec_() != QDialog.Accepted:
        QMessageBox.warning(None, "Login Required", "Password is required to use this application.")
        sys.exit(0)

    if password_must_be_changed():
        forced_dialog = PasswordDialog("Set a New Password", forced=True)
        if forced_dialog.exec_() == QDialog.Accepted:
            set_new_password(forced_dialog.get_password())
        else:
            sys.exit(0)

    window = Dashboard()
    window.show()
    sys.exit(app.exec_())
