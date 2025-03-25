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
    
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip().lower()
        entropy_value = calculate_entropy(section.get_data())
        
        # Packed files often rename sections to known packer names like UPX
        if name in [".upx0", ".upx1", "upx", ".packed"]:
            packed = True
            score += 10
        
        # High entropy suggests compressed or encrypted data, which is often seen in packed malware
        if entropy_value > 7.2:
            packed = True
            score += 10
    
    return score

def analyze_pe(file_path):
    """Analyze a PE file for headers, sections, and packing."""
    try:
        pe = pefile.PE(file_path)
        score = 0
        status = ''
        
        # Malicious files often have very few sections to reduce their footprint
        if pe.FILE_HEADER.NumberOfSections < 3:
            score += 10
        
        # Unusual ImageBase values can indicate obfuscation or unusual execution environments
        if not (0x00400000 <= pe.OPTIONAL_HEADER.ImageBase <= 0x7FFFFFFF):
            score += 10
        
        # Atypical SizeOfHeaders may indicate attempts to evade analysis tools
        if not (0x200 <= pe.OPTIONAL_HEADER.SizeOfHeaders <= 0x1000):
            score += 10
        
        # Very small section alignment can suggest an improperly structured or obfuscated binary
        if pe.OPTIONAL_HEADER.SectionAlignment < 0x200:
            score += 10
        
        # Malware may enable ASLR (Address Space Layout Randomization) to make analysis harder
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40:
            score += 10
        
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_in_section = any(
            section.VirtualAddress <= ep < (section.VirtualAddress + section.Misc_VirtualSize)
            for section in pe.sections
        )
        # If the entry point is outside defined sections, it could indicate shellcode or obfuscation
        if not entry_point_in_section:
            score += 10
        
        for section in pe.sections:
            entropy_value = calculate_entropy(section.get_data())
            # High entropy means the section is likely packed or encrypted, common in malware
            if entropy_value > 7.2:
                score += 10
        
        # If the file is not marked as an executable, it may be trying to disguise itself
        if not (pe.FILE_HEADER.Characteristics & 0x2):
            score += 10
        
        score += detect_packing(pe)

        if score > 50:
            status = 'MALIGN'
        else: status = 'BENIGN'
        
        print(score)

        return status
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def analyze_folder(folder_path, output_file):
    """Analyze all PE files in a folder and save results."""
    results = []
    
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path) and file_name.lower().endswith(".exe"):
            print(f"Analyzing {file_name}...")
            status = analyze_pe(file_path)
            if status is not None:
                results.append((file_name, status))
    
    with open(output_file, "w") as f:
        for file_name, status in results:
            f.write(f"{file_name}: {status}\n")
    
    print(f"Results saved to {output_file}")

# Example usage
folder_path = "path/toPEfolder"  # Change this to your folder path
output_file = "pe_analysis_results.txt"
analyze_folder(folder_path, output_file)