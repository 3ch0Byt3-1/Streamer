from pymem import Pymem
from pymem.pattern import pattern_scan_all
from pymem.memory import read_bytes, write_bytes
import re

# Global storage for original values
original_values_rep = {}  # Stores original values for address + 0x9E
original_values_scan = {}  # Stores original values for address + 0xA2

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

def aimbot_load():
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

def aimbot_on():
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

def aimbot_off():
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

# Example usage
if __name__ == "__main__":
    if aimbot_load():
        if aimbot_on():
            # Do your aimbot stuff here
            input("Press Enter to disable aimbot...")
            aimbot_off()