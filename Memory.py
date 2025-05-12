import pyexpat
import pymem
import pymem.pattern
import pymem.process
import time
import ctypes
import ctypes.wintypes
import os
import sys
from multiprocessing import process
import tempfile
from pymem import *
from pymem.memory import read_bytes, write_bytes
from pymem.pattern import pattern_scan_all
import os
pm = None
from pymem import Pymem
from pymem.pattern import pattern_scan_all
from pymem.memory import read_bytes, write_bytes
import re

# Global storage for original values
original_values_rep = {}  # Stores original values for address + 0x9E
original_values_scan = {}  # Stores original values for address + 0xA2
def scan_and_replace(processName,search,replace):
    pm = pymem.Pymem(processName)
    pm.open_process_from_id(pm.process_id)
    matches = pm.pattern_scan_all(search,return_multiple=True)
    for match in matches:
        if len(matches) == 1:
            print("One Value Found")
            pm.write_bytes(match,replace,len(replace))
            return True
        elif len(matches) > 1:
            print("More Than One Value Found")
            for match in matches:
                pm.write_bytes(match,replace,len(replace))
            return True
        else:
            return False
def get_resource_path(relative_path):
    """ Get absolute path to resource, works for both development and PyInstaller. """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
def get_process(procesName):
    try:
        pm = pymem.Pymem(procesName)
        print('Process Found Please Continue')
        return pm.process_id
    except:
        print('Process Not Found Waiting for process')
        return False

def get_pid(processName):
    pm = pymem.Pymem(processName)
    return pm.process_id

def get_drive_serial_number():
    kernel32 = ctypes.windll.kernel32
    volume_name_buffer = ctypes.create_unicode_buffer(1024)
    file_system_name_buffer = ctypes.create_unicode_buffer(1024)
    serial_number = ctypes.c_ulong(0)
    max_component_length = ctypes.c_ulong(0)
    file_system_flags = ctypes.c_ulong(0)

    success = kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p("C:\\"),
        volume_name_buffer,
        ctypes.sizeof(volume_name_buffer),
        ctypes.byref(serial_number),
        ctypes.byref(max_component_length),
        ctypes.byref(file_system_flags),
        file_system_name_buffer,
        ctypes.sizeof(file_system_name_buffer)
    )

    if success:
        return serial_number.value
    else:
        return None

def get_hwid():
    serial_number = get_drive_serial_number()
    if serial_number:
        return serial_number
    else:
        return None


def adjust_privileges():
    """
    Adjust token privileges to enable SeDebugPrivilege.
    This is necessary to manipulate memory of other processes.
    """
    SE_DEBUG_NAME = "SeDebugPrivilege"
    SE_PRIVILEGE_ENABLED = 0x00000002
    token_handle = ctypes.c_void_p()
    luid = ctypes.c_longlong()
    
    # Open process token
    ctypes.windll.advapi32.OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(),
        0x20 | 0x8,
        ctypes.byref(token_handle)
    )

    # Lookup privilege value
    ctypes.windll.advapi32.LookupPrivilegeValueA(
        0, SE_DEBUG_NAME.encode('ascii'), ctypes.byref(luid)
    )
    
    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", ctypes.c_longlong), ("Attributes", ctypes.c_ulong)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES)]
    
    new_privileges = TOKEN_PRIVILEGES(1, LUID_AND_ATTRIBUTES(luid.value, SE_PRIVILEGE_ENABLED))
    
    # Adjust token privileges
    ctypes.windll.advapi32.AdjustTokenPrivileges(
        token_handle, False, ctypes.byref(new_privileges), 0, None, None
    )
    
    # Close token handle
    ctypes.windll.kernel32.CloseHandle(token_handle)


def find_pattern(pm, module_name, pattern):
    # module = pymem.process.module_from_name(pm.process_handle, module_name)
  
    return pymem.pattern.pattern_scan_all(pm.process_handle, pattern,return_multiple=True)

    
# def aimbot_load():
#     """
#     Loads the aimbot feature by scanning for specific memory patterns in the "HD-Player" process.
#     """
#     try:
#         proc = Pymem("HD-Player")  # Open the process
#     except pymem.exception.ProcessNotFound:
#         return

#     try:
#         if proc:
#             print("\033[31m[>]\033[0m Searching Entity...")
#             global aimbot_addresses
#             # Scanning for entity addresses
#             entity_pattern = mkp("FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43")
#             aimbot_addresses = pattern_scan_all(proc.process_handle, entity_pattern, return_multiple=True)
            
#             if aimbot_addresses:
#                 print("Entities found!")
#             else:
#                 print("No entities found.")
#     except:
#         print("An error occurred while scanning.")
#     finally:
#         if proc:
#             proc.close_process()
#     return "Feature successfully loaded"

# original_values = []
# def aimbot_on(addresses):
#     """
#     Enables aimbot head targeting by modifying memory values.
#     """
#     try:
#         proc = Pymem("HD-Player")
#         if proc:
#             global original_value
#             original_value = []  # Store original memory values
#             for current_entity in aimbot_addresses:
#                 original_value.append((current_entity, read_bytes(proc.process_handle, current_entity + 162, 4)))
#                 value_bytes = read_bytes(proc.process_handle, current_entity + 0xA2, 4)
#                 write_bytes(proc.process_handle, current_entity + 0x9E, value_bytes, len(value_bytes))
#     except pymem.exception.ProcessNotFound:
#         print("Process not found.")
#         return
#     finally:
#         if proc:
#             proc.close_process()
#     return "AIMBOT HEAD ON"

# def aimbot_off(addresses):
#     global original_values
#     pm = pymem.Pymem("HD-Player.exe")
#     for index,address in enumerate(addresses):
#         addressrep = address + 0x9E
#         if original_values[index]:
#             pm.write_int(addressrep, original_values[index])

def mkp(aob: str):
    """Convert AOB string to bytes with wildcards properly handled"""
    byte_pattern = bytearray()
    aob = aob.replace(' ', '')  # Remove all spaces
    
    # Split into pairs and handle wildcards
    for i in range(0, len(aob), 2):
        byte = aob[i:i+2]
        if byte == '??':
            byte_pattern.append(0x00)  # Wildcard represented as 0x00
        else:
            byte_pattern.append(int(byte, 16))
    return bytes(byte_pattern)

# Memory.py (updated functions)

def aimbot_load():
    """Find memory addresses using pattern scanning and return them"""
    try:
        proc = Pymem("HD-Player")
        pattern = mkp(
            "FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 F8 49 16 82 00 00 00 00 F8 94 FC 7F C8 94 FC 7F B8 95 FC 7F E0 94 FC 7F 80 94 FC 7F D0 95 FC 7F E8 95 FC 7F 38 97 FC 7F 98 94 FC 7F 68 94 FC 7F 80 94 FC 7F 50 94 FC 7F 58 95 FC 7F 00 00 00 00 A0 95 FC 7F 40 95 FC 7F 10 95 FC 7F 70 95 FC 7F 28 95 FC 7F 88 95 FC 7F 00 00 00 00 20 8D 3D 80 88 68 88 7F 00 00 00 00 20 77 4C 80 00 00 00 00 80 AA FC 7F 70 B1 AB 81 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 BF 18 26 FC 82 00 00 00 00 00 00 80 BF 00 00 00 00 00 00 00 00"
        )
        
        addresses = pattern_scan_all(
            proc.process_handle,
            pattern,
            return_multiple=True
        )
        
        print(f"Found {len(addresses)} entities")
        return addresses  # Return the list directly
    
    except Exception as e:
        print(f"Scan error: {e}")
        return []
    finally:
        if 'proc' in locals():
            proc.close_process()

def aimbot_on(addresses):
    """Enable aimbot using provided addresses"""
    global original_values_rep, original_values_scan
    
    try:
        proc = Pymem("HD-Player")
        original_values_rep.clear()
        original_values_scan.clear()
        
        for addr in addresses:  # Use the passed addresses
            address_rep = addr + 0x9E
            address_scan = addr + 0xA2
            
            # Store original values
            original_rep = read_bytes(proc.process_handle, address_rep, 4)
            original_scan = read_bytes(proc.process_handle, address_scan, 4)
            
            original_values_rep[address_rep] = original_rep
            original_values_scan[address_scan] = original_scan
            
            # Swap values
            write_bytes(proc.process_handle, address_rep, original_scan, 4)
            write_bytes(proc.process_handle, address_scan, original_rep, 4)
            
        print("Aimbot activated successfully")
        return True
    
    except Exception as e:
        print(f"Activation error: {e}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()

def aimbot_off(addresses):
    """Restore using provided addresses"""
    try:
        proc = Pymem("HD-Player")
        
        for address, value in original_values_rep.items():
            write_bytes(proc.process_handle, address, value, len(value))
        
        for address, value in original_values_scan.items():
            write_bytes(proc.process_handle, address, value, len(value))
            
        print("Aimbot deactivated successfully")
        return True
    
    except Exception as e:
        print(f"Deactivation error: {e}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()

def drag_load():
    """Find memory addresses using pattern scanning"""
    global aimbot_addresses
    aimbot_addresses = []
    
    try:
        proc = Pymem("HD-Player")
        pattern = mkp(
            "FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43"
        )
        
        addresses = pattern_scan_all(
            proc.process_handle,
            pattern,
            return_multiple=True
        )
        
        aimbot_addresses = addresses if addresses else []
        print(f"Found {len(aimbot_addresses)} entities")
        return bool(addresses)
    
    except Exception as e:
        print(f"Scan error: {e}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()


original_drag_values = []
def aimdrag_on(drag_addresses):
    """Enable aimbot by modifying memory values"""
    global original_values_rep, original_values_scan
    
    try:
        proc = Pymem("HD-Player")
        original_values_rep.clear()
        original_values_scan.clear()
        
        for addr in aimbot_addresses:
            address_rep = addr + 0x9E
            address_scan = addr + 0xA2
            
            # Store original values
            original_rep = read_bytes(proc.process_handle, address_rep, 4)
            original_scan = read_bytes(proc.process_handle, address_scan, 4)
            
            original_values_rep[address_rep] = original_rep
            original_values_scan[address_scan] = original_scan
            
            # Swap values
            write_bytes(proc.process_handle, address_rep, original_scan, 4)
            write_bytes(proc.process_handle, address_scan, original_rep, 4)
            
        print("Aimbot activated successfully")
        return True
    
    except Exception as e:
        print(f"Activation error: {e}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()

def aimdrag_off(drag_addresses):
    """Restore original memory values"""
    try:
        proc = Pymem("HD-Player")
        
        # Restore address_rep values
        for address, value in original_values_rep.items():
            write_bytes(proc.process_handle, address, value, len(value))
        
        # Restore address_scan values
        for address, value in original_values_scan.items():
            write_bytes(proc.process_handle, address, value, len(value))
            
        print("Aimbot deactivated successfully")
        return True
    
    except Exception as e:
        print(f"Deactivation error: {e}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()