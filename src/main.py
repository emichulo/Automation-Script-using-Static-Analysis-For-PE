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
        
        # Common packers like UPX rename sections like upx0, upx1, etc, if this appears  it's almost certain the file has been packed.
        if name in [".upx0", ".upx1", "upx", ".packed"]:
            print(f"🚨 Packed section detected: {name}")
            packed = True
            score += 10
        
        #If a packed section also has very high entropy, it likely contains compressed or encrypted malicious code.
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

        # A normal PE have multiple sections (.text, .data, .rdata, .bss, etc),
        # malware authors often reduce the number of sections in packed or obfuscated files to hide code.
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
        
        #The 0x40 flag (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) in DllCharacteristics means that the file
        #  supports Address Space Layout Randomization (ASLR).
        # While ASLR is a security feature, malware often enables it to make analysis harder (avoiding predictable memory addresses).
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40:
            print("⚠️ Suspicious: File has dynamic base enabled.")
            score += 10

        #The Entry Point is where execution starts in a PE file.
        #Normal programs usually have an entry point in .text at a reasonable address (e.g., 0x401000).
        #If it's below 0x1000, the file might be manipulating execution flow, indicating a potential packed or malicious binary.
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint < 0x1000:
            print("⚠️ Suspicious: Entry point in a low memory region.")
            score += 10
        
        # Section Analysis
        print("\n📜 Sections")
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip()
            entropy_value = calculate_entropy(section.get_data())
            print(f"{name}: Virtual Address = {hex(section.VirtualAddress)}, Size = {section.Misc_VirtualSize}, Entropy = {entropy_value:.4f}")
            
            # Entropy measures randomness. Values above 7.2 suggest high compression or encryption, which is common in packed malware.
            # Normal .text sections (code) have entropy between 4.0 and 6.5, while compressed/encrypted sections can reach 7.8+.
            # Packed files often encrypt their contents, and decryption happens at runtime.
            if entropy_value > 7.2:
                print(f"⚠️ High entropy detected in {name}! Possible obfuscation.")
                score += 10
        
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
pe_file = "Executables/exeName.exe"  # Change this to your PE file path
analyze_pe(pe_file)