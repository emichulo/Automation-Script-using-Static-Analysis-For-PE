import pefile
import os
import math
from collections import Counter
from scipy.stats import entropy
import time

packer_signatures = {
    "UPX": [".upx0", ".upx1", "upx", ".packed"],
    "ASPack": [".aspack", ".adata"],
    "FSG": [".fsg", ".FSG!"],
    "MPRESS": [".MPRESS1", ".MPRESS2"],
    "PECompact": [".pec", ".pec1", ".pec2"],
    "Themida": [".themida"],
    "NsPack": [".nsp1", ".nsp0", ".nsp2"],
    "EXE32": [".exe32", ".exepack"],
    "Obsidium": [".obs", ".obsidium"]
}

def calculate_entropy(data):
    """Calculate the entropy of a given byte sequence."""
    score = 0
    max_entropy = 8
    max_score = 20
    pivot = 6
    base = 6

    if not data:
        return 0.0
    counts = Counter(data)
    probabilities = [count / len(data) for count in counts.values()]
    entropy_value = entropy(probabilities, base=2)
        
    # High entropy suggests compressed or encrypted data, which is often seen in packed malware
    if entropy_value < 5.5:
        entropy_value = 0.0
    if entropy_value > max_entropy:
        entropy_value = max_entropy

    if entropy_value <= pivot:
        # Slow curve below pivot (0–pivot)
        normalized = entropy_value / pivot  # scaled 0–1
        score = (max_score * 0.4) * (base ** normalized - 1) / (base - 1)
    else:
        # Fast growth curve from pivot to max
        normalized = (entropy_value - pivot) / (max_entropy - pivot)  # scaled 0–1
        score = (max_score * 0.6) * (base ** normalized - 1) / (base - 1)
        score += max_score * 0.4  # add base from lower range

    return score

def analyze_pe(file_path):
    """Analyze a PE file for headers, sections, and packing."""
    try:
        pe = pefile.PE(file_path)
        score = 0
        status = ''

        with open(file_path, "rb") as f:
            file_data = f.read()
            
        entropy_score = calculate_entropy(file_data) # 1.Calculate entropy score for PE file.
        score += entropy_score

        for section in pe.sections:

            name = section.Name.decode(errors="ignore").strip().lower()
            # 2.Packed files often rename sections to known packer names like UPX, etc.
            if name in packer_signatures:
                score += 10

            entropy_score = calculate_entropy(section.get_data()) # 3.Calculate entropy score for each section.
            score += entropy_score
          
        # 4.Files without an extension are suspicious
        if not os.path.splitext(file_path)[1]:
            score += 10
        
        # 5.Malicious files often have very few sections to reduce their footprint
        if pe.FILE_HEADER.NumberOfSections < 3:
            score += 10
        
        # 6.Unusual ImageBase values can indicate obfuscation or unusual execution environments
        if not (0x00400000 <= pe.OPTIONAL_HEADER.ImageBase <= 0x7FFFFFFF):
            score += 10
        
        # 7.Atypical SizeOfHeaders may indicate attempts to evade analysis tools
        if not (0x200 <= pe.OPTIONAL_HEADER.SizeOfHeaders <= 0x1000):
            score += 10
        
        # 8.Very small section alignment can suggest an improperly structured or obfuscated binary
        if pe.OPTIONAL_HEADER.SectionAlignment < 0x200:
            score += 10
        
        # 9.Malware may enable ASLR (Address Space Layout Randomization) to make analysis harder
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40:
            score += 10
        
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_in_section = any(
            section.VirtualAddress <= ep < (section.VirtualAddress + section.Misc_VirtualSize)
            for section in pe.sections
        )
        # 10.If the entry point is outside defined sections, it could indicate shellcode or obfuscation
        if not entry_point_in_section:
            score += 10
        
        if score > 50:
            status = 'MALIGN'
        else:
            status = 'BENIGN'

        #print(score)
        
        return status, score
    except pefile.PEFormatError:
        print(f"Skipping {file_path}: Not a PE file.")
        return None
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def analyze_folder(folder_path, output_file):
    """Analyze all files in a folder and save results."""
    results = []
    
    # Record the start time
    start_time = time.time()
    
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):  # Process all files regardless of extension
            print(f"Analyzing {file_name}...")
            status, score = analyze_pe(file_path)
            if status is not None:
                results.append((file_name, status, score))
    
    # Record the end time
    end_time = time.time()
    
    # Calculate the time taken
    duration = end_time - start_time
    minutes = int(duration // 60)
    seconds = int(duration % 60)
    
    # Display the total time taken
    print(f"\nTotal time taken: {minutes} minutes and {seconds} seconds")
    
    # Save the results to the output file
    with open(output_file, "w") as f:
        for file_name, status, score in results:
            f.write(f"{file_name}: {status} {score}\n")
    
    print(f"Results saved to {output_file}")

folder_path = "exe"  # Change this to your folder path
output_file = "pe_analysis_results.txt"   # Change this to your txt path if not will be created
analyze_folder(folder_path, output_file)
