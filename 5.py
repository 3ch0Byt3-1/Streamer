from pymem import Pymem
from pymem.pattern import pattern_scan_all
from pymem.memory import read_bytes, write_bytes
import struct

# Global storage
aimbot_addresses = []
original_values_rep = {}  # address + 0x9E
original_values_scan = {}  # address + 0xA2



def mkp(aob: str):
    """Improved AOB pattern converter with better error handling"""
    byte_pattern = bytearray()
    aob = aob.replace(' ', '')
    
    if len(aob) % 2 != 0:
        raise ValueError("AOB pattern must have even number of characters")
    
    for i in range(0, len(aob), 2):
        byte = aob[i:i+2]
        if byte == '??':
            byte_pattern.append(0x00)
        else:
            try:
                byte_pattern.append(int(byte, 16))
            except ValueError:
                raise ValueError(f"Invalid hex byte: {byte}")
    return bytes(byte_pattern)

def aimbot_load():
    """Find memory addresses with validation"""
    global aimbot_addresses
    aimbot_addresses = []
    
    try:
        proc = Pymem("HD-Player")
        pattern = mkp(
            "FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43"
        )
        
        addresses = pattern_scan_all(proc.process_handle, pattern, return_multiple=True)
        
        if not addresses:
            print("No entities found - pattern might be outdated")
            return False
            
        # Validate found addresses by checking typical entity structure
        valid_addresses = []
        for addr in addresses:
            try:
                # Read some values to verify this is really an entity
                test_value = read_bytes(proc.process_handle, addr, 4)
                if len(test_value) == 4:  # Simple validation
                    valid_addresses.append(addr)
            except:
                continue
                
        aimbot_addresses = valid_addresses
        print(f"Found {len(aimbot_addresses)} valid entities")
        return bool(aimbot_addresses)
        
    except Exception as e:
        print(f"Scan error: {str(e)}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()

def aimbot_on():
    """Enable aimbot with better value handling"""
    global original_values_rep, original_values_scan
    
    if not aimbot_addresses:
        print("No valid addresses loaded - run aimbot_load() first")
        return False
        
    try:
        proc = Pymem("HD-Player")
        original_values_rep.clear()
        original_values_scan.clear()
        
        for addr in aimbot_addresses:
            address_rep = addr + 0x9E
            address_scan = addr + 0xA2
            
            try:
                # Read and store original values
                original_rep = read_bytes(proc.process_handle, address_rep, 4)
                original_scan = read_bytes(proc.process_handle, address_scan, 4)
                
                # Convert to floats for debugging
                try:
                    float_rep = struct.unpack('f', original_rep)[0]
                    float_scan = struct.unpack('f', original_scan)[0]
                    print(f"Entity at {hex(addr)} - Original values: {float_rep} (rep), {float_scan} (scan)")
                except:
                    pass
                
                original_values_rep[address_rep] = original_rep
                original_values_scan[address_scan] = original_scan
                
                # Swap values
                write_bytes(proc.process_handle, address_rep, original_scan, 4)
                write_bytes(proc.process_handle, address_scan, original_rep, 4)
                
                # Verify the swap
                new_rep = read_bytes(proc.process_handle, address_rep, 4)
                new_scan = read_bytes(proc.process_handle, address_scan, 4)
                
                if new_rep != original_scan or new_scan != original_rep:
                    print(f"Warning: Swap verification failed for entity at {hex(addr)}")
                
            except Exception as e:
                print(f"Error processing entity at {hex(addr)}: {str(e)}")
                continue
                
        print("Aimbot activated - values swapped")
        return True
        
    except Exception as e:
        print(f"Activation error: {str(e)}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()

def aimbot_off():
    """Restore original values with verification"""
    try:
        proc = Pymem("HD-Player")
        success = True
        
        # Restore address_rep values
        for address, value in original_values_rep.items():
            try:
                write_bytes(proc.process_handle, address, value, len(value))
                # Verify restoration
                current = read_bytes(proc.process_handle, address, len(value))
                if current != value:
                    print(f"Restore failed for address {hex(address)}")
                    success = False
            except Exception as e:
                print(f"Error restoring address {hex(address)}: {str(e)}")
                success = False
                
        # Restore address_scan values
        for address, value in original_values_scan.items():
            try:
                write_bytes(proc.process_handle, address, value, len(value))
                # Verify restoration
                current = read_bytes(proc.process_handle, address, len(value))
                if current != value:
                    print(f"Restore failed for address {hex(address)}")
                    success = False
            except Exception as e:
                print(f"Error restoring address {hex(address)}: {str(e)}")
                success = False
                
        if success:
            print("All values restored successfully")
        else:
            print("Some values failed to restore")
            
        return success
        
    except Exception as e:
        print(f"Deactivation error: {str(e)}")
        return False
    finally:
        if 'proc' in locals():
            proc.close_process()

if __name__ == "__main__":
    print("Loading aimbot...")
    if aimbot_load():
        print("Aimbot loaded successfully")
        input("Press Enter to activate aimbot...")
        if aimbot_on():
            input("Aimbot active. Press Enter to disable...")
            aimbot_off()
        else:
            print("Failed to activate aimbot")
    else:
        print("Failed to load aimbot")