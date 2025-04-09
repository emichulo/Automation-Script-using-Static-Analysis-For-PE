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

def pattern_match_file_header(checker_flags, initial_score):
    # 1 = Low entropy < 6.
    # 2 = Check for packers.  0%
    # 3 = Entropy for each section.
    # 4 = Files w/o extension.  0%
    # 5 = Files with <3 sections. 4%
    # 6 = Unusual ImageBase.      14%
    # 7 = Atypical SizeOfHeaders.  0%
    # 8 = Very small section alignment.  0%
    # 9 = ASLR.                          95%
    # 10 = Entry point is outside defined sections. 30%
    # 11 = Hihg entropy > 7.

    rare_flags = [2, 4, 5, 6, 7, 8, 10, 11]
    moderate_flags = [1, 3, 9]

    rare_hits = sum(1 for i in rare_flags if checker_flags.get(i, False))
    moderate_hits = sum(1 for i in moderate_flags if checker_flags.get(i, False))

    # Pattern logic
    if rare_hits == 2:
        initial_score += 10
    elif rare_hits >= 3 and rare_hits <= 5:
        initial_score += 15
    elif rare_hits >= 5:
        initial_score += 15
    elif rare_hits <= 1 and moderate_hits <= 1:
        initial_score -= 15
    elif rare_hits <= 1 and moderate_hits <= 3:
        initial_score -= 15

    return initial_score

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
        checker_flags = {}

        with open(file_path, "rb") as f:
            file_data = f.read()

        # 1.Calculate entropy score for PE file.
        entropy_score = calculate_entropy(file_data) 
        score += entropy_score
        if entropy_score < 6:
            checker_flags[1] = True
        elif entropy_score > 6:
            checker_flags[11] = True
            

        for section in pe.sections:

            name = section.Name.decode(errors="ignore").strip().lower()
            # 2.Packed files often rename sections to known packer names like UPX, etc.
            if name in packer_signatures:
                score += 10
                checker_flags[2] = True

            # 3.Calculate entropy score for each section.
            entropy_score = calculate_entropy(section.get_data()) 
            score += entropy_score
            if entropy_score > 0:
                checker_flags[3] = True
          
        # 4.Files without an extension are suspicious
        if not os.path.splitext(file_path)[1]:
            score += 20
            checker_flags[4] = True

        # 5.Malicious files often have very few sections to reduce their footprint
        if pe.FILE_HEADER.NumberOfSections < 3:
            score += 19.6
            checker_flags[5] = True
        
        # 6.Unusual ImageBase values can indicate obfuscation or unusual execution environments
        if not (0x00400000 <= pe.OPTIONAL_HEADER.ImageBase <= 0x7FFFFFFF):
            score += 18.4
            checker_flags[6] = True
        
        # 7.Atypical SizeOfHeaders may indicate attempts to evade analysis tools
        if not (0x200 <= pe.OPTIONAL_HEADER.SizeOfHeaders <= 0x1000):
            score += 20
            checker_flags[7] = True
        
        # 8.Very small section alignment can suggest an improperly structured or obfuscated binary
        if pe.OPTIONAL_HEADER.SectionAlignment < 0x200:
            score += 20
            checker_flags[8] = True

        # 9.Malware may enable ASLR (Address Space Layout Randomization) to make analysis harder
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40:
            score += 5
            checker_flags[9] = True

        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_in_section = any(
            section.VirtualAddress <= ep < (section.VirtualAddress + section.Misc_VirtualSize)
            for section in pe.sections
        )
        # 10.If the entry point is outside defined sections, it could indicate shellcode or obfuscation
        if not entry_point_in_section:
            score += 17
            checker_flags[10] = True

        score = pattern_match_file_header(checker_flags, score)
        
        if score > 75:
            status = 'MALIGN'
        else:
            status = 'BENIGN'
    
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
