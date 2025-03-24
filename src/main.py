import pefile
import os
import math
from collections import Counter
from scipy.stats import entropy

def calculate_entropy(data):
    """Calculate the entropy of a given byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    probabilities = [count / len(data) for count in counts.values()]
    return entropy(probabilities, base=2)

def detect_packing(pe):
    """Check for packing indicators (UPX, small sections, high entropy)."""
    packed = False
    score = 0

    print("\n🔍 Checking for packing...")

    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip().lower()
        entropy_value = calculate_entropy(section.get_data())
        print(f"Section {name}: Entropy = {entropy_value:.4f}")
        
        # Common packers like UPX rename sections like upx0, upx1, etc.
        if name in [".upx0", ".upx1", "upx", ".packed"]:
            print(f"🚨 Packed section detected: {name}")
            packed = True
            score += 10
        
        # High entropy suggests compressed or encrypted code
        if entropy_value > 7.2:
            print(f"🚨 High entropy detected in {name}! Possible packing.")
            packed = True
            score += 10
    
    if packed:
        print(f"⚠️ This file might be packed or obfuscated! Score: {score}")
    else:
        print("✅ No obvious packing detected.")
    
    return score

def analyze_pe(file_path):
    """Analyze a PE file for headers, sections, and packing."""
    try:
        pe = pefile.PE(file_path)
        score = 0

        print("=" * 60)
        print(f"🔍 Analyzing: {os.path.basename(file_path)}")
        print("=" * 60)

        # File Header Analysis
        print("\n📜 File Header")
        print(f"Machine           : {hex(pe.FILE_HEADER.Machine)}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"Time Date Stamp   : {hex(pe.FILE_HEADER.TimeDateStamp)}")
        print(f"Characteristics   : {hex(pe.FILE_HEADER.Characteristics)}")

        # A normal PE has multiple sections (.text, .data, .rdata, .bss, etc).
        # Packed or obfuscated files may reduce section count.
        if pe.FILE_HEADER.NumberOfSections < 3:
            print("⚠️ Suspicious: Very few sections detected.")
            score += 10

        # Optional Header Analysis
        print("\n📜 Optional Header")
        print(f"Entry Point       : {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"Image Base        : {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"Size of Image     : {hex(pe.OPTIONAL_HEADER.SizeOfImage)}")
        print(f"Subsystem         : {hex(pe.OPTIONAL_HEADER.Subsystem)}")
        print(f"DLL Characteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")

        # New Check 1: Unusual ImageBase Address
        if not (0x00400000 <= pe.OPTIONAL_HEADER.ImageBase <= 0x7FFFFFFF):
            print("⚠️ Suspicious: Unusual ImageBase address detected!")
            score += 10

        # New Check 2: Abnormal Size of Headers
        if not (0x200 <= pe.OPTIONAL_HEADER.SizeOfHeaders <= 0x1000):
            print("⚠️ Suspicious: Unusual SizeOfHeaders value!")
            score += 10

        # New Check 3: Invalid Section Alignment
        if pe.OPTIONAL_HEADER.SectionAlignment < 0x200:
            print("⚠️ Suspicious: Section alignment is too small!")
            score += 10

        # The 0x40 flag (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) in DllCharacteristics means ASLR is enabled.
        # Malware often enables this to make analysis harder.
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40:
            print("⚠️ Suspicious: File has dynamic base enabled.")
            score += 10

        # New Check 4: Entry Point Anomaly (Outside Defined Sections)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_in_section = any(
            section.VirtualAddress <= ep < (section.VirtualAddress + section.Misc_VirtualSize)
            for section in pe.sections
        )
        if not entry_point_in_section:
            print("⚠️ Suspicious: Entry Point is outside defined sections!")
            score += 10

        # Section Analysis
        print("\n📜 Sections")
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip()
            entropy_value = calculate_entropy(section.get_data())
            print(f"{name}: Virtual Address = {hex(section.VirtualAddress)}, Size = {section.Misc_VirtualSize}, Entropy = {entropy_value:.4f}")
            
            # Entropy above 7.2 suggests obfuscation
            if entropy_value > 7.2:
                print(f"⚠️ High entropy detected in {name}! Possible obfuscation.")
                score += 10

        # New Check 5: Suspicious Characteristics Flags
        if not (pe.FILE_HEADER.Characteristics & 0x2):  # 0x2 = Executable Image
            print("⚠️ Suspicious: File is not marked as an executable!")
            score += 10
        if pe.FILE_HEADER.Characteristics & 0x2000:  # 0x2000 = DLL
            print("ℹ️ Note: This is a DLL file.")

        # Checking Packing
        score += detect_packing(pe)

        print("\n🔍 Final Score: ", score)
        if score >= 30:
            print("🚨 High probability of being a packed/malicious file!")
        else:
            print("✅ File does not show strong malicious indicators.")
        
    except Exception as e:
        print(f"❌ Error processing file: {e}")

# Example Usage
pe_file = "yourPATH.exe"  # Change this to your PE file path
analyze_pe(pe_file)
