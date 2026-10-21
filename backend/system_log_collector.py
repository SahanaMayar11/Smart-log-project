import os
import sys
import re
import json
import time
import socket
import platform
import psutil
import ctypes
import subprocess
import winreg
import html
from datetime import datetime, timedelta, timezone
from ctypes import wintypes

# ==============================================================================
# 0. SYSTEM ENVIRONMENT METADATA (ACCURATE HOST IDENTIFICATION)
# ==============================================================================
def get_system_environment_metadata():
    """Returns verified local system metadata (Computer, Hostname, User, Domain, OS, IP)."""
    hostname = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'ROCKY'
    username = os.environ.get('USERNAME') or 'Admin'
    domain = os.environ.get('USERDOMAIN') or hostname
    os_name = f"Windows {platform.release()}" if platform.system() == 'Windows' else platform.system()
    ip_addr = '127.0.0.1'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip_addr = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip_addr = socket.gethostbyname(hostname)
        except Exception:
            pass

    return {
        'computer': hostname,
        'hostname': hostname,
        'user': username,
        'domain': domain,
        'os': os_name,
        'ip_address': ip_addr,
        'source_label': f"{hostname} — LOCAL WINDOWS MACHINE"
    }

SYS_INFO = get_system_environment_metadata()


# ==============================================================================
# 1. ADVANCED PE HEADER & APPLICATION NAME RESOLVER
# ==============================================================================
def get_file_version_metadata(file_path):
    """
    Extracts authentic Windows PE metadata (FileDescription, ProductName, CompanyName)
    directly via Win32 version.dll without external dependencies.
    """
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(file_path, None)
        if size == 0:
            return None
        res = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(file_path, 0, size, res):
            return None

        p_trans = ctypes.c_void_p()
        u_len = ctypes.c_uint()
        if ctypes.windll.version.VerQueryValueW(res, r'\VarFileInfo\Translation', ctypes.byref(p_trans), ctypes.byref(u_len)):
            trans_arr = ctypes.cast(p_trans, ctypes.POINTER(wintypes.WORD))
            lang = trans_arr[0]
            codepage = trans_arr[1]
            for prop in ['FileDescription', 'ProductName', 'InternalName', 'CompanyName']:
                sub_block = f'\\StringFileInfo\\{lang:04x}{codepage:04x}\\{prop}'
                p_val = ctypes.c_wchar_p()
                val_len = ctypes.c_uint()
                if ctypes.windll.version.VerQueryValueW(res, sub_block, ctypes.byref(p_val), ctypes.byref(val_len)) and p_val.value:
                    val = p_val.value.strip()
                    if val and not val.lower().endswith('.exe') and len(val) > 2:
                        return val
    except Exception:
        pass
    return None

KNOWN_APP_MAP = {
    # Browsers & Internet
    'chrome.exe': 'Google Chrome',
    'msedge.exe': 'Microsoft Edge',
    'firefox.exe': 'Mozilla Firefox',
    'brave.exe': 'Brave Browser',
    'opera.exe': 'Opera Browser',
    'tor.exe': 'Tor Browser',
    'safari.exe': 'Safari Browser',

    # Development & IDEs
    'code.exe': 'Visual Studio Code',
    'devenv.exe': 'Visual Studio',
    'py.exe': 'Python Launcher',
    'python.exe': 'Python Interpreter',
    'pythonw.exe': 'Python Background Process',
    'git.exe': 'Git Version Control',
    'windowsterminal.exe': 'Windows Terminal',
    'wt.exe': 'Windows Terminal',
    'cmd.exe': 'Command Prompt',
    'powershell.exe': 'Windows PowerShell',
    'pwsh.exe': 'PowerShell 7',
    'antigravity.exe': 'Antigravity',
    'node.exe': 'Node.js Runtime',
    'docker.exe': 'Docker Desktop',
    'dockerd.exe': 'Docker Engine',

    # Windows Native Utilities & Tools
    'explorer.exe': 'File Explorer',
    'notepad.exe': 'Notepad',
    'control.exe': 'Control Panel',
    'systemsettings.exe': 'Windows Settings',
    'systemsettingsadminflows.exe': 'Windows Settings',
    'taskmgr.exe': 'Task Manager',
    'regedit.exe': 'Registry Editor',
    'mmc.exe': 'Microsoft Management Console',
    'services.exe': 'Windows Service Manager',
    'sechealthui.exe': 'Windows Security',
    'securityhealthsystray.exe': 'Windows Security Tray',
    'lsass.exe': 'Local Security Authority',
    'svchost.exe': 'Host Process for Windows Services',
    'sihost.exe': 'Shell Infrastructure Host',
    'ctfmon.exe': 'CTF Loader (Text Input Host)',
    'taskhostw.exe': 'Host Process for Windows Tasks',
    'runtimebroker.exe': 'Runtime Broker',
    'smartscreen.exe': 'Windows Defender SmartScreen',
    'msmpeng.exe': 'Windows Defender Antivirus',
    'nissrv.exe': 'Windows Defender Network Inspection',
    'sppsvc.exe': 'Software Protection Platform',
    'werfault.exe': 'Windows Error Reporting',
    'msiexec.exe': 'Windows Installer',
    'winlogon.exe': 'Windows Logon',

    # Store, Media, Office & Communications
    'whatsapp.exe': 'WhatsApp',
    'whatsapp.root.exe': 'WhatsApp',
    'whatsappdesktop.exe': 'WhatsApp',
    'whatsappnativehost.exe': 'WhatsApp',
    'whatsapphost.exe': 'WhatsApp',
    'whatsapp.roothost.exe': 'WhatsApp',
    'cameraapp.exe': 'Camera',
    'windowscamera.exe': 'Camera',
    'calculatorapp.exe': 'Calculator',
    'calculator.exe': 'Calculator',
    'calc.exe': 'Calculator',
    'snippingtool.exe': 'Snipping Tool',
    'screensketch.exe': 'Snipping Tool',
    'photosapp.exe': 'Windows Photos',
    'photos.exe': 'Windows Photos',
    'winstore.app.exe': 'Microsoft Store',
    'spotify.exe': 'Spotify',
    'slack.exe': 'Slack',
    'discord.exe': 'Discord',
    'teams.exe': 'Microsoft Teams',
    'msteams.exe': 'Microsoft Teams',
    'ms-teams.exe': 'Microsoft Teams',
    'zoom.exe': 'Zoom Workplace',
    'vlc.exe': 'VLC Media Player',
    'winword.exe': 'Microsoft Word',
    'excel.exe': 'Microsoft Excel',
    'powerpnt.exe': 'Microsoft PowerPoint',
    'outlook.exe': 'Microsoft Outlook',
    'acrord32.exe': 'Adobe Acrobat',
    'acrobat.exe': 'Adobe Acrobat',
    'hxtsr.exe': 'Microsoft Outlook Process',
    'hxoutlook.exe': 'Microsoft Outlook Process',
    'phoneexperiencehost.exe': 'Phone Link',
    'xboxpcapp.exe': 'Xbox App',
    'time.exe': 'Windows Clock',
    'onedrive.exe': 'Microsoft OneDrive'
}

GUI_APPS = {
    'chrome.exe', 'code.exe', 'notepad.exe', 'calculatorapp.exe', 'calculator.exe', 'calc.exe',
    'explorer.exe', 'msedge.exe', 'firefox.exe', 'whatsapp.exe', 'whatsapp.root.exe', 'whatsappdesktop.exe',
    'whatsappnativehost.exe', 'spotify.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe', 'slack.exe',
    'discord.exe', 'teams.exe', 'msteams.exe', 'ms-teams.exe', 'zoom.exe', 'vlc.exe', 'steam.exe', 'brave.exe', 'opera.exe',
    'windowsterminal.exe', 'wt.exe', 'control.exe', 'systemsettings.exe', 'taskmgr.exe', 'cameraapp.exe',
    'windowscamera.exe', 'snippingtool.exe', 'photosapp.exe', 'photos.exe', 'winstore.app.exe', 'xboxpcapp.exe',
    'acrord32.exe', 'acrobat.exe', 'antigravity.exe'
}

SYSTEM_PROVIDERS = {
    'bthusb', 'microsoft-windows-wmi-activity', 'windows-error-reporting',
    'microsoft-windows-kernel-power', 'microsoft-windows-kernel-general',
    'microsoft-windows-distributedcom', 'microsoft-windows-security-auditing',
    'service control manager', 'microsoft-windows-filteringplatform',
    'microsoft-windows-time-service', 'microsoft-windows-dhcpv6-client',
    'microsoft-windows-networkprofile', 'microsoft-windows-power-troubleshooter'
}

def is_system_provider_name(prov_name):
    """Returns True if provider represents a Windows system subsystem/driver rather than a user desktop app."""
    if not prov_name:
        return True
    p_lower = str(prov_name).lower().strip()
    if p_lower in SYSTEM_PROVIDERS:
        return True
    if p_lower.startswith('microsoft-windows-') and not any(k in p_lower for k in ('chrome', 'code', 'notepad', 'calculator', 'photos', 'camera', 'whatsapp')):
        return True
    if p_lower.endswith('driver') or 'subsystem' in p_lower or 'hardware' in p_lower:
        return True
    return False

def resolve_application_name(process_name, exe_path=None, cmdline=None):
    """
    Resolves raw executable or provider name to human-readable application name in priority order:
    1. System Provider detection -> 'System Activity' / 'System Error'.
    2. WhatsApp resolution.
    3. Known Application Table.
    4. Win32 PE version / product metadata (FileDescription, ProductName).
    5. Clean executable basename (e.g. 'mytool.exe' -> 'Mytool').
    6. Clean Windows Provider name fallback.
    """
    if not process_name:
        return 'System Activity'

    clean_name = str(process_name).strip()
    # Strip trailing event id brackets like 'Microsoft-Windows-Security-Auditing[4688]'
    if '[' in clean_name and clean_name.endswith(']'):
        clean_name = clean_name.split('[')[0].strip()
    if clean_name.endswith(':'):
        clean_name = clean_name[:-1].strip()

    lower_name = clean_name.lower()

    # Check if raw provider name was passed
    if is_system_provider_name(lower_name):
        return 'System Activity'

    exe_str = str(exe_path or '').lower()
    cmd_str = str(cmdline or '').lower()

    # 1. WhatsApp distinction
    if 'whatsapp' in lower_name or 'whatsapp' in exe_str or 'whatsapp' in cmd_str:
        if 'helper' in lower_name or 'helper' in exe_str or 'crashpad' in lower_name:
            return 'WhatsApp Helper Process'
        return 'WhatsApp'

    # 2. Check Known Application Lookup Table
    if lower_name in KNOWN_APP_MAP:
        return KNOWN_APP_MAP[lower_name]

    # Extract clean basename if full path was provided
    base_file = os.path.basename(clean_name).lower()
    if base_file in KNOWN_APP_MAP:
        return KNOWN_APP_MAP[base_file]

    # 3. Check PE Header Version Metadata if valid binary on disk
    if exe_path and os.path.exists(exe_path):
        pe_desc = get_file_version_metadata(exe_path)
        if pe_desc:
            return pe_desc

    # Try resolving standard System32 / Windows path for PE info
    standard_paths = [
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', clean_name),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), clean_name)
    ]
    for sp in standard_paths:
        if os.path.exists(sp):
            pe_desc = get_file_version_metadata(sp)
            if pe_desc:
                return pe_desc

    # 4. Formatted Clean Executable Fallback (e.g. 'mytool.exe' -> 'Mytool')
    if lower_name.endswith('.exe'):
        base = clean_name[:-4]
        formatted = base.replace('_', ' ').replace('-', ' ').title()
        return formatted if formatted.strip() else 'Application'

    # 5. Clean Windows Provider Formatter Fallback
    if 'microsoft-windows-' in lower_name:
        return clean_name.replace('Microsoft-Windows-', 'Windows ').replace('-', ' ').title()

    formatted_general = clean_name.replace('_', ' ').replace('-', ' ').title()
    return formatted_general if formatted_general.strip() else 'System Activity'


def resolve_action_name(process_name, is_start=True, app_name=None):
    """Resolves human-readable action name (Application Started vs Process Started)."""
    p_lower = (process_name or '').lower()
    a_lower = (app_name or '').lower()
    is_gui = p_lower in GUI_APPS or 'whatsapp' in p_lower or 'whatsapp' in a_lower or a_lower in (
        'whatsapp', 'calculator', 'notepad', 'google chrome', 'visual studio code', 'camera',
        'control panel', 'file explorer', 'spotify', 'microsoft word', 'microsoft excel',
        'microsoft teams', 'snipping tool', 'windows settings', 'settings', 'task manager'
    )
    if is_start:
        if is_gui:
            return 'Application Started'
        return 'Process Started'
    else:
        if is_gui:
            return 'Application Closed'
        return 'Process Terminated'


# ==============================================================================
# 2. COLLECTOR SELF-PID FILTER & PROCESS LIFECYCLE TRACKER
# ==============================================================================
CURRENT_PROCESS_PID = os.getpid()

def is_collector_polling_noise(new_proc_name, creator_proc_name=None, creator_pid=None, self_pids=None):
    """
    Distinguishes internal collector polling commands (e.g. python.exe launching wevtutil.exe)
    from genuine user actions (e.g. user launching powershell.exe, cmd.exe, chrome.exe).
    """
    new_lower = (new_proc_name or '').lower()
    creator_lower = (creator_proc_name or '').lower()

    if self_pids and creator_pid in self_pids:
        if 'wevtutil' in new_lower or 'powershell' in new_lower:
            return True

    if 'wevtutil' in new_lower and 'python' in creator_lower:
        return True

    return False


class ProcessLifecycleTracker:
    """
    Monitors native Windows process start and termination events in real time using psutil.
    Emits 4688 (Process Creation) and 4689 (Termination) with parent process resolution.
    """
    def __init__(self):
        self.sys_meta = get_system_environment_metadata()
        self.hostname = self.sys_meta['hostname']
        self.known_processes = {}  # {pid: {name, exe, ppid, parent_name, username, create_time, cmdline}}
        self.self_pids = {CURRENT_PROCESS_PID}
        self.record_counter = 100000
        self.initialized = False
        self._initialize_process_snapshot()

    def _get_next_record_id(self):
        self.record_counter += 1
        return self.record_counter

    def _is_self_process(self, pid, ppid=None, name=None, exe=None):
        """Checks if a process belongs to Smart-Log collector or internal query commands."""
        if pid in self.self_pids:
            return True
        name_lower = (name or '').lower()
        exe_lower = (exe or '').lower()
        # Suppress internal polling loop commands only
        if 'wevtutil' in name_lower or 'wevtutil' in exe_lower:
            return True
        return False

    def _initialize_process_snapshot(self):
        """Snapshots initial system processes on startup so baseline processes aren't dumped as new."""
        try:
            for p in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'username', 'create_time', 'cmdline']):
                try:
                    info = p.info
                    pid = info['pid']
                    if pid == 0 or pid == 4:
                        continue
                    if self._is_self_process(pid, info.get('ppid'), info.get('name'), info.get('exe')):
                        self.self_pids.add(pid)
                        continue
                    cmdline_str = ' '.join(info.get('cmdline') or [])
                    self.known_processes[pid] = {
                        'pid': pid,
                        'name': info.get('name') or 'unknown.exe',
                        'exe': info.get('exe') or '',
                        'ppid': info.get('ppid') or 0,
                        'username': info.get('username') or f"{self.hostname}\\System",
                        'create_time': info.get('create_time') or time.time(),
                        'cmdline': cmdline_str
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            self.initialized = True
        except Exception as e:
            print(f"[PROCESS TRACKER] Snapshot init warning: {e}")

    def scan_process_changes(self):
        """
        Scans current processes against known process table.
        Emits real PROCESS_STARTED (4688) and PROCESS_TERMINATED (4689) events with parent process context.
        """
        if not self.initialized:
            self._initialize_process_snapshot()
            return []

        current_pids = {}
        new_events = []
        now = datetime.now()
        now_iso = now.isoformat()
        now_time = now.strftime("%H:%M:%S")

        # 1. Scan currently active processes
        for p in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'username', 'create_time', 'cmdline']):
            try:
                info = p.info
                pid = info['pid']
                if pid == 0 or pid == 4:
                    continue

                ppid = info.get('ppid') or 0
                name = info.get('name') or 'unknown.exe'
                exe = info.get('exe') or ''
                user = info.get('username') or f"{self.hostname}\\User"
                create_time = info.get('create_time') or time.time()
                cmdline_str = ' '.join(info.get('cmdline') or [])

                if self._is_self_process(pid, ppid, name, exe):
                    self.self_pids.add(pid)
                    continue

                current_pids[pid] = {
                    'pid': pid,
                    'name': name,
                    'exe': exe,
                    'ppid': ppid,
                    'username': user,
                    'create_time': create_time,
                    'cmdline': cmdline_str
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # 2. Detect NEW Process Starts (Event ID 4688)
        for pid, pdata in current_pids.items():
            if pid not in self.known_processes:
                name = pdata['name']
                exe = pdata['exe']
                cmdline = pdata.get('cmdline', '')
                app_name = resolve_application_name(name, exe, cmdline)
                ppid = pdata['ppid']
                parent_name = self.known_processes.get(ppid, {}).get('name', 'explorer.exe')
                parent_app = resolve_application_name(parent_name)
                user_raw = pdata['username']
                user_clean = user_raw.split('\\')[-1] if '\\' in user_raw else user_raw
                domain = user_raw.split('\\')[0] if '\\' in user_raw else self.hostname
                rec_id = self._get_next_record_id()
                action_name = resolve_action_name(name, is_start=True, app_name=app_name)

                is_gui = action_name == 'Application Started'
                event_type = 'APPLICATION START' if is_gui else 'PROCESS START'
                desc = f"{app_name} was started by {user_clean} on computer {self.hostname}."
                clean_msg = f"A new process was created. Application: {app_name}, Process Name: {name}, PID: {pid}, Parent PID: {ppid}, Parent Process: {parent_name} ({parent_app}), User: {user_clean}, Path: {exe or 'N/A'}."

                event = {
                    'id': f"sec-4688-{rec_id}",
                    'timestamp': now_iso,
                    'time': now_time,
                    'hostname': self.hostname,
                    'computer': self.hostname,
                    'user': user_clean,
                    'domain': domain,
                    'os': self.sys_meta['os'],
                    'ip_address': self.sys_meta['ip_address'],
                    'source': 'LOCAL WINDOWS MACHINE',
                    'channel': 'Security',
                    'provider': 'Microsoft-Windows-Security-Auditing',
                    'event_id': 4688,
                    'record_id': rec_id,
                    'level': 'INFORMATION',
                    'task': 'Process Creation',
                    'event_type': event_type,
                    'action': action_name,
                    'application': app_name,
                    'application_name': app_name,
                    'process': name,
                    'process_name': name,
                    'raw_process_path': exe,
                    'executable_path': exe,
                    'process_id': pid,
                    'pid': pid,
                    'creator_pid': ppid,
                    'parent_pid': ppid,
                    'parent_process_id': ppid,
                    'creator_process': parent_name,
                    'parent_process': parent_name,
                    'parent_process_name': parent_name,
                    'parent_application': parent_app,
                    'command_line': cmdline or name,
                    'account_name': user_clean,
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                }
                new_events.append(event)
                self.known_processes[pid] = pdata

        # 3. Detect Process Terminations (Event ID 4689)
        terminated_pids = []
        for pid, pdata in self.known_processes.items():
            if pid not in current_pids:
                name = pdata['name']
                exe = pdata.get('exe', '')
                cmdline = pdata.get('cmdline', '')
                app_name = resolve_application_name(name, exe, cmdline)
                user_raw = pdata.get('username', f"{self.hostname}\\User")
                user_clean = user_raw.split('\\')[-1] if '\\' in user_raw else user_raw
                domain = user_raw.split('\\')[0] if '\\' in user_raw else self.hostname
                rec_id = self._get_next_record_id()
                action_name = resolve_action_name(name, is_start=False, app_name=app_name)

                is_gui = action_name == 'Application Closed'
                event_type = 'APPLICATION CLOSE' if is_gui else 'PROCESS TERMINATION'
                desc = f"{app_name} was closed by {user_clean} on computer {self.hostname}."
                clean_msg = f"A process has exited. Application: {app_name}, Process Name: {name}, PID: {pid}, User: {user_clean}."

                event = {
                    'id': f"sec-4689-{rec_id}",
                    'timestamp': now_iso,
                    'time': now_time,
                    'hostname': self.hostname,
                    'computer': self.hostname,
                    'user': user_clean,
                    'domain': domain,
                    'os': self.sys_meta['os'],
                    'ip_address': self.sys_meta['ip_address'],
                    'source': 'LOCAL WINDOWS MACHINE',
                    'channel': 'Security',
                    'provider': 'Microsoft-Windows-Security-Auditing',
                    'event_id': 4689,
                    'record_id': rec_id,
                    'level': 'INFORMATION',
                    'task': 'Process Termination',
                    'event_type': event_type,
                    'action': action_name,
                    'application': app_name,
                    'application_name': app_name,
                    'process': name,
                    'process_name': name,
                    'raw_process_path': exe,
                    'executable_path': exe,
                    'process_id': pid,
                    'pid': pid,
                    'creator_pid': pdata.get('ppid', 0),
                    'parent_pid': pdata.get('ppid', 0),
                    'parent_process_id': pdata.get('ppid', 0),
                    'creator_process': 'explorer.exe',
                    'parent_process': 'explorer.exe',
                    'parent_process_name': 'explorer.exe',
                    'parent_application': 'Windows File Explorer',
                    'command_line': cmdline or name,
                    'account_name': user_clean,
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                }
                new_events.append(event)
                terminated_pids.append(pid)

        for pid in terminated_pids:
            self.known_processes.pop(pid, None)

        return new_events

process_tracker = ProcessLifecycleTracker()


# ==============================================================================
# 3. CAMERA & HARDWARE PRIVACY ACCESS TRACKER
# ==============================================================================
class CameraAccessTracker:
    """
    Tracks authentic Windows Camera and Webcam hardware usage events via
    Windows CapabilityAccessManager ConsentStore registry tracking.
    """
    def __init__(self):
        self.sys_meta = get_system_environment_metadata()
        self.hostname = self.sys_meta['hostname']
        self.last_starts = {}  # {app_key: last_start_time}
        self.record_counter = 400000
        self.initialized = False
        self._init_snapshot()

    def _init_snapshot(self):
        """Initial snapshot of camera access state."""
        try:
            base_paths = [
                r'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam',
                r'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged'
            ]
            for sub in base_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub) as key:
                        num_subkeys, _, _ = winreg.QueryInfoKey(key)
                        for i in range(num_subkeys):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as app_key:
                                    st, _ = winreg.QueryValueEx(app_key, 'LastUsedTimeStart')
                                    self.last_starts[subkey_name] = st
                            except Exception:
                                pass
                except Exception:
                    pass
            self.initialized = True
        except Exception:
            pass

    def scan_camera_changes(self):
        """Emits CAMERA ACCESS events when camera hardware usage is detected."""
        if not self.initialized:
            self._init_snapshot()
            return []

        events = []
        now = datetime.now()
        now_iso = now.isoformat()
        now_time = now.strftime("%H:%M:%S")

        base_paths = [
            r'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam',
            r'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged'
        ]

        for sub in base_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub) as key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as app_key:
                                start_time, _ = winreg.QueryValueEx(app_key, 'LastUsedTimeStart')
                                stop_time = 0
                                try:
                                    stop_time, _ = winreg.QueryValueEx(app_key, 'LastUsedTimeStop')
                                except Exception:
                                    pass

                                prev_start = self.last_starts.get(subkey_name, 0)
                                if start_time > prev_start and start_time > 0:
                                    # Resolve application name from subkey
                                    app_name = 'Camera Access — Application Not Identified'
                                    proc_name = 'camera_device.exe'
                                    clean_key = subkey_name.replace('#', '\\')

                                    if 'Google' in clean_key or 'chrome' in clean_key.lower():
                                        app_name = 'Google Meet / Google Chrome'
                                        proc_name = 'chrome.exe'
                                    elif 'WindowsCamera' in clean_key or 'Camera' in clean_key:
                                        app_name = 'Windows Camera'
                                        proc_name = 'WindowsCamera.exe'
                                    elif 'WhatsApp' in clean_key:
                                        app_name = 'WhatsApp'
                                        proc_name = 'WhatsApp.exe'
                                    elif 'Teams' in clean_key:
                                        app_name = 'Microsoft Teams'
                                        proc_name = 'ms-teams.exe'
                                    elif 'Zoom' in clean_key:
                                        app_name = 'Zoom Workplace'
                                        proc_name = 'Zoom.exe'
                                    elif 'Edge' in clean_key.lower():
                                        app_name = 'Microsoft Edge'
                                        proc_name = 'msedge.exe'
                                    elif os.path.basename(clean_key).endswith('.exe'):
                                        proc_name = os.path.basename(clean_key)
                                        app_name = resolve_application_name(proc_name, clean_key)

                                    self.record_counter += 1
                                    rec_id = self.record_counter
                                    desc = f"{app_name} accessed the integrated camera on computer {self.hostname}."
                                    clean_msg = f"Camera device access detected. Application: {app_name}, Process: {proc_name}, Device: Integrated Camera, User: {self.sys_meta['user']}."

                                    events.append({
                                        'id': f"cam-access-{rec_id}",
                                        'timestamp': now_iso,
                                        'time': now_time,
                                        'hostname': self.hostname,
                                        'computer': self.hostname,
                                        'user': self.sys_meta['user'],
                                        'domain': self.sys_meta['domain'],
                                        'os': self.sys_meta['os'],
                                        'ip_address': self.sys_meta['ip_address'],
                                        'source': 'LOCAL WINDOWS MACHINE',
                                        'channel': 'Security',
                                        'provider': 'Microsoft-Windows-CapabilityAccessManager',
                                        'event_id': 5000,
                                        'record_id': rec_id,
                                        'level': 'INFORMATION',
                                        'task': 'Device Access',
                                        'event_type': 'CAMERA ACCESS',
                                        'action': 'Camera Access',
                                        'device': 'Integrated Camera',
                                        'application': app_name,
                                        'application_name': app_name,
                                        'process': proc_name,
                                        'process_name': proc_name,
                                        'raw_process_path': clean_key,
                                        'executable_path': clean_key,
                                        'process_id': 0,
                                        'pid': 'Camera Device',
                                        'creator_pid': 0,
                                        'parent_pid': 0,
                                        'parent_process_id': 0,
                                        'creator_process': 'System',
                                        'parent_process': 'System',
                                        'parent_process_name': 'System',
                                        'parent_application': 'Windows System',
                                        'command_line': proc_name,
                                        'account_name': self.sys_meta['user'],
                                        'status': 'NORMAL',
                                        'is_anomaly': 0,
                                        'severity': 'Normal',
                                        'description': desc,
                                        'message': clean_msg
                                    })
                                    self.last_starts[subkey_name] = start_time
                        except Exception:
                            pass
            except Exception:
                pass
        return events

camera_tracker = CameraAccessTracker()


# ==============================================================================
# 3. BATTERY & CHARGER TELEMETRY TRACKER
# ==============================================================================
class PowerTelemetryTracker:
    """
    Monitors real laptop battery and AC charger connection state via psutil.
    Emits POWER_CONNECTED and POWER_DISCONNECTED telemetry on state changes.
    """
    def __init__(self):
        self.hostname = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'windows-pc'
        self.last_plugged = None
        self.last_percent = None
        self.record_counter = 200000
        self._init_state()

    def _init_state(self):
        try:
            battery = psutil.sensors_battery()
            if battery:
                self.last_plugged = battery.power_plugged
                self.last_percent = int(battery.percent)
        except Exception:
            pass

    def scan_power_changes(self):
        new_events = []
        try:
            battery = psutil.sensors_battery()
            if not battery:
                return []

            curr_plugged = battery.power_plugged
            curr_percent = int(battery.percent)
            now_iso = datetime.now().isoformat()

            if self.last_plugged is not None and curr_plugged != self.last_plugged:
                self.record_counter += 1
                rec_id = self.record_counter

                if curr_plugged:
                    action = "Power Source Connected"
                    desc = "AC power/charging cable connected. The computer is now running on external power and the battery is charging."
                    clean_msg = f"AC power connected. Battery state: CHARGING ({curr_percent}%)."
                else:
                    action = "Power Source Disconnected"
                    desc = "Charging cable/AC power removed. The computer is now running on battery power."
                    clean_msg = f"AC power disconnected. Battery state: DISCHARGING ({curr_percent}%)."

                event = {
                    'timestamp': now_iso,
                    'hostname': self.hostname,
                    'computer': self.hostname,
                    'channel': 'System',
                    'provider': 'Microsoft-Windows-Power-Troubleshooter',
                    'event_id': 105,
                    'record_id': rec_id,
                    'level': 'INFORMATION',
                    'task': 'Power Troubleshooter',
                    'event_type': 'POWER_EVENT',
                    'action': action,
                    'application': 'Power Management',
                    'application_name': 'Power Management',
                    'process': 'System',
                    'process_name': 'System',
                    'process_id': 'Not provided by Windows event',
                    'pid': 'Not provided by Windows event',
                    'user': f"{self.hostname}\\SYSTEM",
                    'battery_percent': curr_percent,
                    'power_plugged': curr_plugged,
                    'description': desc,
                    'message': clean_msg
                }
                new_events.append(event)

            self.last_plugged = curr_plugged
            self.last_percent = curr_percent
        except Exception:
            pass

        return new_events

power_tracker = PowerTelemetryTracker()


# ==============================================================================
# 4. FOREGROUND APPLICATION & BROWSER WINDOW TRACKER
# ==============================================================================
class ForegroundWindowTracker:
    """
    Detects currently focused foreground window and active application name.
    Extracts active application telemetry in real time when user opens or uses apps.
    """
    def __init__(self):
        self.hostname = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'windows-pc'
        self.last_fg_pid = None
        self.last_title = ""
        self.last_emit_time = 0

    def get_foreground_info(self):
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            if not hwnd:
                return None

            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not pid.value or pid.value <= 4:
                return None

            title_buf = ctypes.create_unicode_buffer(512)
            ctypes.windll.user32.GetWindowTextW(hwnd, title_buf, 512)
            title = title_buf.value.strip()
            if not title or title in ('Task Switching', 'Program Manager'):
                return None

            p = psutil.Process(pid.value)
            proc_name = p.name()
            exe_path = ''
            try:
                exe_path = p.exe()
            except Exception:
                pass

            lower_title = title.lower()
            if proc_name.lower() == 'explorer.exe' and ('control panel' in lower_title or 'all control panel' in lower_title):
                app_name = 'Control Panel'
            elif proc_name.lower() == 'explorer.exe' and ('recycle bin' in lower_title):
                app_name = 'Recycle Bin'
            else:
                app_name = resolve_application_name(proc_name, exe_path)
            user_raw = p.username() if hasattr(p, 'username') else f"{self.hostname}\\Admin"
            user_clean = user_raw.split('\\')[-1] if '\\' in user_raw else user_raw

            return {
                'pid': pid.value,
                'process_name': proc_name,
                'application_name': app_name,
                'window_title': title,
                'username': user_clean,
                'executable_path': exe_path
            }
        except Exception:
            return None

    def scan_foreground_changes(self):
        """Detects when the user switches to a new active/foreground window or interacts with an app (WhatsApp, Chrome, Notepad, etc.)."""
        info = self.get_foreground_info()
        if not info:
            return []

        pid = info['pid']
        title = info['window_title']
        proc_name = info['process_name']
        app_name = info['application_name']
        now_ts = time.time()

        # If same window and checked within 15 seconds, don't duplicate
        if pid == self.last_fg_pid and title == self.last_title and (now_ts - self.last_emit_time) < 15.0:
            return []

        self.last_fg_pid = pid
        self.last_title = title
        self.last_emit_time = now_ts

        now = datetime.now()
        now_iso = now.strftime('%Y-%m-%d %H:%M:%S')
        now_time = now.strftime("%H:%M:%S")
        user_clean = info.get('username') or 'Admin'

        action_name = "Active in Foreground"
        desc = f"{app_name} is active in the foreground and being used by {user_clean}."
        clean_msg = f"User active on {app_name}. Window: \"{title}\", Process: {proc_name} (PID: {pid})."

        event = {
            'id': f"fg-{pid}-{int(now_ts)}",
            'timestamp': now_iso,
            'time': now_time,
            'hostname': self.hostname,
            'computer': self.hostname,
            'user': user_clean,
            'domain': self.hostname,
            'os': SYS_INFO.get('os', 'Windows 10/11'),
            'ip_address': SYS_INFO.get('ip_address', '127.0.0.1'),
            'source': 'LOCAL WINDOWS MACHINE',
            'channel': 'Security',
            'provider': 'Microsoft-Windows-Security-Auditing',
            'event_id': 4688,
            'record_id': int(now_ts),
            'level': 'INFORMATION',
            'task': 'User Activity',
            'event_type': 'USER_ACTIVITY',
            'action': action_name,
            'application': app_name,
            'application_name': app_name,
            'process': proc_name,
            'process_name': proc_name,
            'raw_process_path': info.get('executable_path', ''),
            'executable_path': info.get('executable_path', ''),
            'process_id': pid,
            'pid': pid,
            'creator_pid': 0,
            'parent_pid': 0,
            'parent_process_id': 0,
            'creator_process': 'explorer.exe',
            'parent_process': 'explorer.exe',
            'parent_process_name': 'explorer.exe',
            'parent_application': 'Windows File Explorer',
            'command_line': title,
            'account_name': user_clean,
            'status': 'NORMAL',
            'is_anomaly': 0,
            'severity': 'Normal',
            'description': desc,
            'message': clean_msg,
            'what_happened': desc,
            'why_suspicious': 'This activity is consistent with normal active user interaction.',
            'recommended_action': 'No action required. Normal foreground window activity.'
        }
        return [event]

foreground_tracker = ForegroundWindowTracker()


# ==============================================================================
# 5. WINDOWS EVENT LOG TELEMETRY (NATIVE WEVTUTIL — ZERO POWERSHELL NOISE)
# ==============================================================================
def parse_wevtutil_xml_snippet(xml_text, default_channel='System'):
    """Parses native wevtutil XML events into human-readable structured dictionaries."""
    events = []
    if not xml_text:
        return events

    raw_blocks = xml_text.split("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>")
    default_host = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'Rocky'

    for block in raw_blocks:
        if not block.strip():
            continue

        try:
            # 1. Extract EventID
            event_id = 1000
            if '<EventID' in block:
                id_part = block.split('<EventID')[1].split('</EventID>')[0]
                if '>' in id_part:
                    id_val = id_part.split('>')[1].strip()
                    event_id = int(id_val) if id_val.isdigit() else 1000

            # 2. Extract Provider Name
            provider = 'Microsoft-Windows-System'
            if "Provider Name='" in block:
                provider = block.split("Provider Name='")[1].split("'")[0]
            elif 'Provider Name="' in block:
                provider = block.split('Provider Name="')[1].split('"')[0]

            # 3. Extract Channel
            channel = default_channel
            if '<Channel>' in block:
                channel = block.split('<Channel>')[1].split('</Channel>')[0].strip()

            # 4. Extract EventRecordID
            record_id = 0
            if '<EventRecordID>' in block:
                rec_part = block.split('<EventRecordID>')[1].split('</EventRecordID>')[0].strip()
                record_id = int(rec_part) if rec_part.isdigit() else 0

            # 5. Extract Computer / Hostname
            hostname = default_host
            if '<Computer>' in block:
                comp_part = block.split('<Computer>')[1].split('</Computer>')[0].strip()
                if comp_part:
                    hostname = comp_part

            # 6. Extract Execution ProcessID
            exec_pid = 4
            if "Execution ProcessID='" in block:
                p_str = block.split("Execution ProcessID='")[1].split("'")[0].strip()
                exec_pid = int(p_str) if p_str.isdigit() else 4

            # 7. Extract TimeCreated (Convert UTC to Local System Time)
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if "TimeCreated SystemTime='" in block:
                ts_raw = block.split("TimeCreated SystemTime='")[1].split("'")[0].strip()
                try:
                    clean_ts = ts_raw.replace('Z', '').replace('z', '').split('.')[0].replace(' ', 'T')
                    dt_utc = datetime.fromisoformat(clean_ts).replace(tzinfo=timezone.utc)
                    dt_local = dt_utc.astimezone()
                    ts = dt_local.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    ts = ts_raw.split('.')[0] if ts_raw else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            time_str = ts.split('T')[1].split('.')[0] if 'T' in ts else (ts.split(' ')[1] if ' ' in ts else ts[-8:])

            # 8. Extract Level
            level_num = 4
            if '<Level>' in block:
                lvl_str = block.split('<Level>')[1].split('</Level>')[0].strip()
                level_num = int(lvl_str) if lvl_str.isdigit() else 4

            level_map = {1: 'CRITICAL', 2: 'ERROR', 3: 'WARNING', 4: 'INFORMATION', 0: 'INFORMATION'}
            level = level_map.get(level_num, 'INFORMATION')

            # 9. Extract RenderingInfo Message
            rendered_msg = ""
            if '<RenderingInfo' in block and '<Message>' in block:
                try:
                    raw_rm = block.split('<Message>')[1].split('</Message>')[0].strip()
                    unescaped = html.unescape(raw_rm)
                    unescaped = unescaped.replace('&#13;&#10;', ' ').replace('&#13;', ' ').replace('&#10;', ' ').replace('&#9;', ' ')
                    rendered_msg = " ".join(unescaped.replace('\r', ' ').replace('\n', ' ').split())
                except Exception:
                    pass

            # 10. Extract Message / Data dictionary cleanly using regex to avoid string split artifacts
            data_dict = {}
            for m in re.finditer(r"<Data(?:\s+Name=['\"]([^'\"]*)['\"])?>([^<]*)</Data>", block, re.DOTALL):
                name, val = m.group(1), m.group(2)
                val = html.unescape(val or '').replace('&#13;&#10;', ' ').replace('&#13;', ' ').replace('&#10;', ' ').replace('&#9;', ' ')
                val = " ".join(val.replace('\r', ' ').replace('\n', ' ').split())
                if name:
                    data_dict[name] = val
                elif val:
                    data_dict[f"data_{len(data_dict)}"] = val

            # ==================================================================
            # SPECIFIC EVENT TYPE HANDLERS FOR HUMAN-READABLE TELEMETRY
            # ==================================================================

            # Security 4688: Process Creation
            if event_id == 4688:
                new_proc_name = data_dict.get('NewProcessName', '')
                proc_name = os.path.basename(new_proc_name) if new_proc_name else 'unknown.exe'
                creator_pid_raw = data_dict.get('ProcessId', '0x0')
                ppid = int(creator_pid_raw, 16) if str(creator_pid_raw).startswith('0x') else int(creator_pid_raw or 0)
                parent_proc_path = data_dict.get('ParentProcessName', '')
                parent_name = os.path.basename(parent_proc_path) if parent_proc_path else 'explorer.exe'

                if is_collector_polling_noise(new_proc_name, parent_proc_path, ppid, {CURRENT_PROCESS_PID}):
                    continue

                app_name = resolve_application_name(proc_name, new_proc_name)
                new_pid_raw = data_dict.get('NewProcessId', '0x0')
                pid = int(new_pid_raw, 16) if str(new_pid_raw).startswith('0x') else int(new_pid_raw or 0)
                cmd_line = data_dict.get('CommandLine', proc_name)
                user_raw = data_dict.get('SubjectUserName', data_dict.get('TargetUserName', f"{hostname}\\User"))
                user_clean = user_raw.split('\\')[-1] if '\\' in user_raw else user_raw
                domain = data_dict.get('SubjectDomainName', data_dict.get('TargetDomainName', hostname))
                action_name = resolve_action_name(proc_name, is_start=True, app_name=app_name)
                parent_app = resolve_application_name(parent_name)

                desc = f"{app_name} was started by {user_clean} on computer {hostname}."
                clean_msg = f"A new process was created. Application: {app_name}, Process Name: {proc_name}, PID: {pid}, Parent Process: {parent_name} ({parent_app}), User: {user_clean}."

                events.append({
                    'id': f"sec-4688-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Security',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': level,
                    'task': 'Process Creation',
                    'event_type': 'PROCESS_START',
                    'action': action_name,
                    'application': app_name,
                    'application_name': app_name,
                    'process': proc_name,
                    'process_name': proc_name,
                    'raw_process_path': new_proc_name,
                    'executable_path': new_proc_name,
                    'process_id': pid,
                    'pid': pid,
                    'creator_pid': ppid,
                    'parent_pid': ppid,
                    'parent_process_id': ppid,
                    'creator_process': parent_name,
                    'parent_process': parent_name,
                    'parent_process_name': parent_name,
                    'parent_application': parent_app,
                    'command_line': cmd_line,
                    'user': user_clean,
                    'account_name': user_clean,
                    'domain': domain,
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # Security 4689: Process Termination
            elif event_id == 4689:
                proc_name_raw = data_dict.get('ProcessName', '')
                proc_name = os.path.basename(proc_name_raw) if proc_name_raw else 'unknown.exe'
                
                if is_collector_polling_noise(proc_name_raw, None, None, {CURRENT_PROCESS_PID}):
                    continue

                app_name = resolve_application_name(proc_name, proc_name_raw)
                pid_raw = data_dict.get('ProcessId', '0x0')
                pid = int(pid_raw, 16) if str(pid_raw).startswith('0x') else int(pid_raw or 0)
                user_raw = data_dict.get('SubjectUserName', f"{hostname}\\User")
                user_clean = user_raw.split('\\')[-1] if '\\' in user_raw else user_raw
                domain = data_dict.get('SubjectDomainName', hostname)
                action_name = resolve_action_name(proc_name, is_start=False, app_name=app_name)

                desc = f"{app_name} was closed by {user_clean} on computer {hostname}."
                clean_msg = f"A process has exited. Application: {app_name}, Process Name: {proc_name}, PID: {pid}, User: {user_clean}."

                events.append({
                    'id': f"sec-4689-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Security',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': level,
                    'task': 'Process Termination',
                    'event_type': 'PROCESS_TERMINATION',
                    'action': action_name,
                    'application': app_name,
                    'application_name': app_name,
                    'process': proc_name,
                    'process_name': proc_name,
                    'raw_process_path': proc_name_raw,
                    'executable_path': proc_name_raw,
                    'process_id': pid,
                    'pid': pid,
                    'creator_pid': 0,
                    'parent_pid': 0,
                    'parent_process_id': 0,
                    'creator_process': 'explorer.exe',
                    'parent_process': 'explorer.exe',
                    'parent_process_name': 'explorer.exe',
                    'parent_application': 'File Explorer',
                    'command_line': proc_name,
                    'user': user_clean,
                    'account_name': user_clean,
                    'domain': domain,
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # Security 4624: User Logon
            elif event_id == 4624:
                user_raw = str(data_dict.get('TargetUserName', 'User')).replace('</Data', '').strip()
                domain = str(data_dict.get('TargetDomainName', hostname)).replace('</Data', '').strip()
                logon_type = str(data_dict.get('LogonType', '2')).strip()
                desc = f"User {user_raw} logged on successfully to computer {hostname}."
                clean_msg = f"An account was successfully logged on. Account Name: {user_raw}, Domain: {domain}, Logon Type: {logon_type}."

                events.append({
                    'id': f"sec-4624-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Security',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'INFORMATION',
                    'task': 'Logon',
                    'event_type': 'USER_LOGON',
                    'action': 'User Logon',
                    'logon_type': logon_type,
                    'auth_result': 'success',
                    'application': 'Windows Logon',
                    'application_name': 'Windows Logon',
                    'process': 'winlogon.exe',
                    'process_name': 'winlogon.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': user_raw,
                    'account_name': user_raw,
                    'domain': domain,
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # Security 4625: Failed Logon
            elif event_id == 4625:
                user_raw = str(data_dict.get('TargetUserName', 'User')).replace('</Data', '').strip()
                domain = str(data_dict.get('TargetDomainName', hostname)).replace('</Data', '').strip()
                logon_type = str(data_dict.get('LogonType', '2')).strip()
                status_code = str(data_dict.get('Status', '0xc000006d')).strip()
                sub_status = str(data_dict.get('SubStatus', '0xc000006a')).strip()
                desc = f"Failed logon attempt detected for account {user_raw} on computer {hostname}."
                clean_msg = f"An account failed to log on. Account Name: {user_raw}, Domain: {domain}, Status: {status_code}, SubStatus: {sub_status}."

                events.append({
                    'id': f"sec-4625-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Security',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'WARNING',
                    'task': 'Logon Attempt',
                    'event_type': 'FAILED_LOGON',
                    'action': 'Logon Failure',
                    'logon_type': logon_type,
                    'status_code': status_code,
                    'sub_status': sub_status,
                    'auth_result': 'failure',
                    'application': 'Windows Logon',
                    'application_name': 'Windows Logon',
                    'process': 'winlogon.exe',
                    'process_name': 'winlogon.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': user_raw,
                    'account_name': user_raw,
                    'domain': domain,
                    'status': 'ANOMALY',
                    'is_anomaly': 1,
                    'severity': 'High',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # Security 4800: Workstation Locked
            elif event_id == 4800:
                user_raw = str(data_dict.get('TargetUserName', 'User')).replace('</Data', '').strip()
                domain = str(data_dict.get('TargetDomainName', hostname)).replace('</Data', '').strip()
                desc = f"Workstation was locked by user {user_raw} on computer {hostname}."
                clean_msg = f"The workstation was locked. Target Account: {user_raw}, Domain: {domain}."

                events.append({
                    'id': f"sec-4800-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Security',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'INFORMATION',
                    'task': 'Lock / Unlock',
                    'event_type': 'WORKSTATION_LOCKED',
                    'action': 'Workstation Locked',
                    'application': 'Windows Lock Screen',
                    'application_name': 'Windows Lock Screen',
                    'process': 'logonui.exe',
                    'process_name': 'logonui.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': user_raw,
                    'account_name': user_raw,
                    'domain': domain,
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # Security 4801: Workstation Unlocked
            elif event_id == 4801:
                user_raw = str(data_dict.get('TargetUserName', 'User')).replace('</Data', '').strip()
                domain = str(data_dict.get('TargetDomainName', hostname)).replace('</Data', '').strip()
                desc = f"Workstation was unlocked by user {user_raw} on computer {hostname}."
                clean_msg = f"The workstation was unlocked. Target Account: {user_raw}, Domain: {domain}."

                events.append({
                    'id': f"sec-4801-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Security',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'INFORMATION',
                    'task': 'Lock / Unlock',
                    'event_type': 'WORKSTATION_UNLOCKED',
                    'action': 'Workstation Unlocked',
                    'auth_result': 'success',
                    'application': 'Windows Lock Screen',
                    'application_name': 'Windows Lock Screen',
                    'process': 'logonui.exe',
                    'process_name': 'logonui.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': user_raw,
                    'account_name': user_raw,
                    'domain': domain,
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # System 7036: Service State Changed
            elif event_id == 7036 and ('Service' in provider or channel == 'System'):
                srv_name = data_dict.get('param1', 'Windows Service')
                srv_state = data_dict.get('param2', 'running')
                desc = rendered_msg or f"The {srv_name} service entered the {srv_state} state on computer {hostname}."
                clean_msg = f"Service state change. Service: {srv_name}, State: {srv_state}."

                events.append({
                    'id': f"sys-7036-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows System',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': level,
                    'task': 'Service Control',
                    'event_type': 'SERVICE_EVENT',
                    'action': 'Service State Changed',
                    'application': 'Windows Service Manager',
                    'application_name': 'Windows Service Manager',
                    'process': 'services.exe',
                    'process_name': 'services.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': f"{hostname}\\SYSTEM",
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # System 6005 / 6006 / 1074: Windows Startup / Shutdown
            elif event_id in (6005, 6006, 1074):
                is_start = (event_id == 6005)
                act = "Windows Startup" if is_start else "Windows Shutdown"
                desc = f"Windows operating system {'started up' if is_start else 'shutdown was initiated'} on computer {hostname}."

                events.append({
                    'id': f"sys-{event_id}-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows System',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'INFORMATION',
                    'task': 'Operating System State',
                    'event_type': 'SYSTEM_STATE',
                    'action': act,
                    'application': 'Windows Operating System',
                    'application_name': 'Windows Operating System',
                    'process': 'System',
                    'process_name': 'System',
                    'pid': 4,
                    'process_id': 4,
                    'user': f"{hostname}\\SYSTEM",
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': desc
                })
                continue

            # Application 1000 / 1002: Application Crash or Hang
            elif event_id in (1000, 1002):
                fault_app = data_dict.get('AppName', data_dict.get('data_0', 'Application'))
                app_clean = resolve_application_name(fault_app)
                is_hang = (event_id == 1002)
                act = "Application Hang" if is_hang else "Application Crash"
                desc = f"{app_clean} {'stopped interacting with Windows' if is_hang else 'encountered an unexpected error and crashed'} on computer {hostname}."

                events.append({
                    'id': f"app-{event_id}-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Application',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'ERROR',
                    'task': 'Application Fault',
                    'event_type': 'APPLICATION_CRASH',
                    'action': act,
                    'application': app_clean,
                    'application_name': app_clean,
                    'process': fault_app,
                    'process_name': fault_app,
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': f"{hostname}\\User",
                    'status': 'ANOMALY',
                    'is_anomaly': 1,
                    'severity': 'High',
                    'description': desc,
                    'message': rendered_msg or desc
                })
                continue

            # PowerShell Operational: 40961, 40962, 4104
            elif 'powershell' in channel.lower() or 'powershell' in provider.lower():
                act = "PowerShell Activity"
                desc = rendered_msg or f"Routine Windows PowerShell engine lifecycle telemetry ({event_id}) recorded on {hostname}."

                events.append({
                    'id': f"ps-{event_id}-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows PowerShell',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': level,
                    'task': 'PowerShell Execution',
                    'event_type': 'POWERSHELL_TELEMETRY',
                    'action': act,
                    'application': 'Windows PowerShell',
                    'application_name': 'Windows PowerShell',
                    'process': 'powershell.exe',
                    'process_name': 'powershell.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': f"{hostname}\\User",
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': desc
                })
                continue

            # WLAN AutoConfig: Wireless connectivity status (Normal background telemetry)
            elif 'wlan-autoconfig' in provider.lower() or 'wlan' in provider.lower():
                desc = rendered_msg or f"WLAN wireless network interface event {event_id} on {hostname}."
                clean_msg = f"Wireless network interface event {event_id}. Routine Wi-Fi connection telemetry."

                events.append({
                    'id': f"net-wlan-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows WLAN AutoConfig',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'INFORMATION',
                    'task': 'Network Connectivity',
                    'event_type': 'NETWORK_CONNECTIVITY',
                    'action': 'Wireless Connectivity Event',
                    'application': 'Windows Wireless Service',
                    'application_name': 'Windows Wireless Service',
                    'process': 'svchost.exe',
                    'process_name': 'svchost.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': f"{hostname}\\SYSTEM",
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': clean_msg
                })
                continue

            # Windows Defender: 1000, 1001, 1116, 1117
            elif 'defender' in channel.lower() or 'defender' in provider.lower():
                is_threat = event_id in (1116, 1117)
                act = "Malware Detected" if is_threat else "Antivirus Scan Completed"
                desc = rendered_msg or f"Windows Defender recorded security activity on computer {hostname}."

                events.append({
                    'id': f"def-{event_id}-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Defender',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': 'WARNING' if is_threat else 'INFORMATION',
                    'task': 'Defender Antivirus',
                    'event_type': 'SECURITY_EVENT',
                    'action': act,
                    'application': 'Windows Defender',
                    'application_name': 'Windows Defender',
                    'process': 'MsMpEng.exe',
                    'process_name': 'MsMpEng.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': f"{hostname}\\SYSTEM",
                    'status': 'ANOMALY' if is_threat else 'NORMAL',
                    'is_anomaly': 1 if is_threat else 0,
                    'severity': 'Critical' if is_threat else 'Normal',
                    'description': desc,
                    'message': desc
                })
                continue

            # Task Scheduler: 106, 200, 201
            elif 'taskscheduler' in channel.lower() or 'taskscheduler' in provider.lower():
                act = "Scheduled Task Executed"
                desc = rendered_msg or f"Windows Task Scheduler executed task on computer {hostname}."

                events.append({
                    'id': f"task-{event_id}-{record_id}",
                    'timestamp': ts,
                    'time': time_str,
                    'hostname': hostname,
                    'computer': hostname,
                    'channel': channel,
                    'provider': provider,
                    'source': 'Windows Task Scheduler',
                    'event_id': event_id,
                    'record_id': record_id,
                    'level': level,
                    'task': 'Task Scheduler',
                    'event_type': 'TASK_SCHEDULER',
                    'action': act,
                    'application': 'Task Scheduler',
                    'application_name': 'Task Scheduler',
                    'process': 'taskhostw.exe',
                    'process_name': 'taskhostw.exe',
                    'pid': exec_pid,
                    'process_id': exec_pid,
                    'user': f"{hostname}\\SYSTEM",
                    'status': 'NORMAL',
                    'is_anomaly': 0,
                    'severity': 'Normal',
                    'description': desc,
                    'message': desc
                })
                continue

            # ==================================================================
            # GENERAL FALLBACK WITH RESOLVED APPLICATION NAME
            # ==================================================================
            app_resolved = resolve_application_name(provider)
            clean_msg = rendered_msg or (" | ".join(data_dict.values()) if data_dict else f"Windows {channel} event {event_id} from {app_resolved}.")
            clean_msg = " ".join(clean_msg.replace('\r', ' ').replace('\n', ' ').split())
            desc = rendered_msg or f"Windows {channel} event {event_id} logged by {app_resolved} on computer {hostname}."

            events.append({
                'id': f"win-{event_id}-{record_id}",
                'timestamp': ts,
                'time': time_str,
                'hostname': hostname,
                'computer': hostname,
                'channel': channel,
                'provider': provider,
                'event_id': event_id,
                'record_id': record_id,
                'level': level,
                'task': 'General',
                'event_type': 'SYSTEM_EVENT',
                'action': 'Event Logged',
                'application': app_resolved,
                'application_name': app_resolved,
                'process': 'System',
                'process_name': 'System',
                'pid': exec_pid,
                'process_id': exec_pid,
                'parent_pid': 0,
                'parent_process': 'System',
                'user': f"{hostname}\\SYSTEM",
                'status': 'NORMAL' if level == 'INFORMATION' else 'ANOMALY',
                'is_anomaly': 0 if level == 'INFORMATION' else 1,
                'severity': 'Normal' if level == 'INFORMATION' else ('Warning' if level == 'WARNING' else 'High'),
                'description': desc,
                'message': clean_msg
            })
        except Exception:
            continue

    return events


def parse_powershell_date(date_str):
    """Parses PowerShell timestamp /Date(ms)/ or standard date string into ISO datetime."""
    if not date_str:
        return datetime.now().isoformat()

    if isinstance(date_str, str) and date_str.startswith('/Date(') and date_str.endswith(')/'):
        try:
            ms = int(date_str[6:-2].split('+')[0].split('-')[0])
            return datetime.fromtimestamp(ms / 1000.0).isoformat()
        except Exception:
            return datetime.now().isoformat()

    return str(date_str).replace(' ', 'T')


def collect_windows_system_logs(hours=24, max_events=2000):
    """
    Collects real Windows Event Logs from System, Application, Security for past 24 hours.
    Preserved for Historical 24-Hour Analysis (/upload -> LAST 24 HOURS).
    """
    hostname = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'windows-server'
    raw_events = []
    scanned_channels = []
    unavailable_channels = []
    admin_warning = None
    channel_diagnostics = {}

    ps_script = f"""
    $ErrorActionPreference = 'SilentlyContinue'
    $cutoff = (Get-Date).AddHours(-{hours})
    $maxPerChannel = [math]::Max(400, [math]::Ceiling({max_events} / 2))
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $sysCount = 0
    $appCount = 0
    $secCount = 0
    $secStatus = "NOT_ATTEMPTED"

    # 1. System Channel
    try {{
        $sys = Get-WinEvent -FilterHashtable @{{LogName='System'; StartTime=$cutoff}} -MaxEvents $maxPerChannel
        if ($sys) {{
            foreach ($e in $sys) {{ $results.Add($e) }}
            $sysCount = if ($sys -is [array]) {{ $sys.Count }} else {{ 1 }}
        }}
    }} catch {{}}

    # 2. Application Channel
    try {{
        $app = Get-WinEvent -FilterHashtable @{{LogName='Application'; StartTime=$cutoff}} -MaxEvents $maxPerChannel
        if ($app) {{
            foreach ($e in $app) {{ $results.Add($e) }}
            $appCount = if ($app -is [array]) {{ $app.Count }} else {{ 1 }}
        }}
    }} catch {{}}

    # 3. Security Channel (Requires Administrator privileges)
    try {{
        $sec = Get-WinEvent -FilterHashtable @{{LogName='Security'; StartTime=$cutoff}} -MaxEvents $maxPerChannel
        if ($sec) {{
            foreach ($e in $sec) {{ $results.Add($e) }}
            $secCount = if ($sec -is [array]) {{ $sec.Count }} else {{ 1 }}
            $secStatus = "SUCCESS"
        }}
    }} catch {{}}

    Write-Output "DIAG:SYS=$sysCount;APP=$appCount;SEC=$secCount;SEC_STATUS=$secStatus"

    $results | Select-Object TimeCreated, LogName, ProviderName, Id, LevelDisplayName, TaskDisplayName, RecordId, Message -First {max_events} | ConvertTo-Json -Compress -Depth 2
    """

    try:
        process = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

        stdout = process.stdout.strip()
        diag_line = None

        for line in stdout.splitlines():
            if line.startswith("DIAG:"):
                diag_line = line
                break

        if diag_line:
            parts = diag_line.replace("DIAG:", "").split(";")
            diag_map = {}
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                    diag_map[k] = v

            sys_c = int(diag_map.get("SYS", 0))
            app_c = int(diag_map.get("APP", 0))
            sec_c = int(diag_map.get("SEC", 0))
            sec_st = diag_map.get("SEC_STATUS", "NOT_ATTEMPTED")

            channel_diagnostics["System"] = {"status": "AVAILABLE", "count": sys_c}
            channel_diagnostics["Application"] = {"status": "AVAILABLE", "count": app_c}
            scanned_channels.extend(["System", "Application"])

            if sec_st == "SUCCESS":
                channel_diagnostics["Security"] = {"status": "AVAILABLE", "count": sec_c}
                scanned_channels.append("Security")
            else:
                channel_diagnostics["Security"] = {
                    "status": "PERMISSION_REQUIRED",
                    "count": 0,
                    "reason": "Windows Security logs require Administrator privileges."
                }
                unavailable_channels.append("Security")
                admin_warning = "Some Windows Security Event Logs require Administrator privileges."
        else:
            scanned_channels.extend(["System", "Application"])

        json_start_bracket = stdout.find("[")
        json_start_brace = stdout.find("{")

        if json_start_bracket != -1 and (json_start_brace == -1 or json_start_bracket < json_start_brace):
            json_str = stdout[json_start_bracket:]
        elif json_start_brace != -1:
            json_str = stdout[json_start_brace:]
        else:
            json_str = ""

        if json_str:
            try:
                raw_json = json.loads(json_str)
                if isinstance(raw_json, dict):
                    raw_events = [raw_json]
                elif isinstance(raw_json, list):
                    raw_events = raw_json
            except Exception:
                raw_events = []

    except Exception as e:
        print(f"Warning: Windows Event Log collection exception: {e}")
        raw_events = []

    normalized_records = []
    syslog_lines = []

    for item in raw_events:
        ts = parse_powershell_date(item.get("TimeCreated"))
        channel = str(item.get("LogName") or "System").strip()
        provider = str(item.get("ProviderName") or "WindowsProvider").replace(" ", "-").strip()
        event_id = item.get("Id") or 1000
        level = str(item.get("LevelDisplayName") or "Information").upper().strip()
        record_id = item.get("RecordId") or 0
        task = str(item.get("TaskDisplayName") or "General").strip()

        raw_msg = str(item.get("Message") or "Windows event record generated.").replace("\r", " ").replace("\n", " ").strip()
        clean_msg = " ".join(raw_msg.split())
        app_name = resolve_application_name(provider)

        record = {
            "timestamp": ts,
            "hostname": hostname,
            "channel": channel,
            "provider": provider,
            "event_id": event_id,
            "level": level,
            "task": task,
            "record_id": record_id,
            "application_name": app_name,
            "process_name": "System",
            "message": clean_msg
        }
        normalized_records.append(record)

        syslog_line = f"{ts} {hostname} {provider}[{event_id}]: {level} - [Channel:{channel}|RecordID:{record_id}] {clean_msg}"
        syslog_lines.append(syslog_line)

    scan_status = "Full Windows Event Log scan" if not unavailable_channels else "Partial Windows Event Log scan"
    limit_reached = len(normalized_records) >= max_events
    limit_message = f"{len(normalized_records)} of {max_events} events collected — maximum limit reached." if limit_reached else None

    return {
        "hostname": hostname,
        "hours": hours,
        "max_events": max_events,
        "total_collected": len(normalized_records),
        "records": normalized_records,
        "log_content": "\n".join(syslog_lines),
        "scanned_channels": scanned_channels,
        "unavailable_channels": unavailable_channels,
        "scan_status": scan_status,
        "admin_warning": admin_warning,
        "channel_diagnostics": channel_diagnostics,
        "limit_reached": limit_reached,
        "limit_message": limit_message
    }


# ==============================================================================
# 6. REAL-TIME LIVE WINDOWS TELEMETRY COLLECTOR (MULTI-CHANNEL)
# ==============================================================================
def collect_new_windows_events(last_record_ids=None, max_events=100):
    """
    Collects NEW real Windows telemetry events across multiple channels:
    1. Real Process Start (4688) & Process Termination (4689)
    2. Camera & Hardware Privacy Access Events
    3. Battery & Charger Power telemetry
    4. Multi-channel native Windows Event Logs: System, Application, PowerShell, Defender, TaskScheduler
    5. Zero internal polling loop noise.
    """
    hostname = socket.gethostname() or os.environ.get('COMPUTERNAME') or 'Rocky'
    if last_record_ids is None:
        last_record_ids = {}

    updated_record_ids = dict(last_record_ids)
    all_new_events = []
    scanned_channels = ["Security", "System", "Application", "PowerShell", "Defender", "TaskScheduler"]
    unavailable_channels = []
    admin_warning = None

    # 0. User Foreground Active Window Events (WhatsApp, Chrome, VS Code, Notepad, File Explorer, etc.)
    fg_events = foreground_tracker.scan_foreground_changes()
    for fe in fg_events:
        all_new_events.append(fe)

    # 1. Process Lifecycle Events (Chrome, VS Code, Notepad, Calculator, WhatsApp, File Explorer, etc.)
    proc_events = process_tracker.scan_process_changes()
    for pe in proc_events:
        all_new_events.append(pe)

    # 2. Camera & Hardware Privacy Access Events
    cam_events = camera_tracker.scan_camera_changes()
    for ce in cam_events:
        all_new_events.append(ce)

    # 3. Power & Battery Status Events
    pwr_events = power_tracker.scan_power_changes()
    for pwe in pwr_events:
        all_new_events.append(pwe)

    # 4. Multi-Channel Native Windows Event Logs
    channel_query_map = {
        'Security': ('Security', '/q:*[System[(EventID=4688 or EventID=4689 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4800 or EventID=4801)]]'),
        'System': ('System', None),
        'Application': ('Application', None),
        'PowerShell': ('Microsoft-Windows-PowerShell/Operational', None),
        'Defender': ('Microsoft-Windows-Windows Defender/Operational', None),
        'TaskScheduler': ('Microsoft-Windows-TaskScheduler/Operational', None)
    }

    for ch_key, (channel_name, query_filter) in channel_query_map.items():
        try:
            cmd = ['wevtutil', 'qe', channel_name, '/c:25', '/rd:true', '/f:RenderedXml']
            if query_filter:
                cmd = ['wevtutil', 'qe', channel_name, query_filter, '/c:25', '/rd:true', '/f:RenderedXml']

            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=4,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                parsed_evts = parse_wevtutil_xml_snippet(res.stdout, default_channel=ch_key)
                
                # Sort ascending by record_id so reverse wevtutil output (/rd:true) does not skip records
                parsed_evts.sort(key=lambda x: x.get('record_id', 0))

                last_seen_id = updated_record_ids.get(ch_key, 0)
                
                if last_seen_id == 0 and parsed_evts:
                    # Initial run: take latest 5 events for immediate display and initialize watermark
                    new_evts_to_process = parsed_evts[-5:]
                    for ev in new_evts_to_process:
                        all_new_events.append(ev)
                        rec_id = ev.get('record_id', 0)
                        if rec_id > updated_record_ids.get(ch_key, 0):
                            updated_record_ids[ch_key] = rec_id
                else:
                    for ev in parsed_evts:
                        rec_id = ev.get('record_id', 0)
                        if last_seen_id > 0 and rec_id <= last_seen_id:
                            continue
                        
                        all_new_events.append(ev)
                        if rec_id > updated_record_ids.get(ch_key, 0):
                            updated_record_ids[ch_key] = rec_id
            elif res.returncode == 5:
                if ch_key not in unavailable_channels:
                    unavailable_channels.append(ch_key)
        except Exception:
            pass

    # Sort new records chronologically
    all_new_events.sort(key=lambda x: x.get('timestamp', ''))

    # Limit to max_events
    if len(all_new_events) > max_events:
        all_new_events = all_new_events[-max_events:]

    return {
        "hostname": hostname,
        "computer": hostname,
        "source_label": f"{hostname} — LOCAL WINDOWS MACHINE",
        "user": SYS_INFO['user'],
        "domain": SYS_INFO['domain'],
        "os": SYS_INFO['os'],
        "ip_address": SYS_INFO['ip_address'],
        "new_count": len(all_new_events),
        "records": all_new_events,
        "last_record_ids": updated_record_ids,
        "scanned_channels": scanned_channels,
        "unavailable_channels": unavailable_channels,
        "admin_warning": admin_warning
    }


if __name__ == '__main__':
    print("Testing Live System Collector...")
    res = collect_new_windows_events()
    print(f"Collected {res['new_count']} new Windows telemetry events.")
    for r in res['records']:
        print(f"[{r.get('event_type')}] {r.get('application_name')} ({r.get('process_name')}) PID: {r.get('pid')} -> {r.get('description')}")
