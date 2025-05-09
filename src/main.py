import pefile
import os
import math
from collections import Counter
from scipy.stats import entropy
import time
import datetime
import yara

# Load YARA rules once
yara_rules_packed = yara.compile(filepath="Yara/packer.yar")
yara_rules_strings = yara.compile(filepath="Yara/suspicious_strings.yar")
yara_rules_dlls = yara.compile(filepath="Yara/Dlls.yar")
yara_rules_ip = yara.compile(filepath="Yara/ip.yar")
yara_rules_url = yara.compile(filepath="Yara/url.yar")

def pattern_match_file_header(checker_flags, initial_score):
    
    # 1 = Low entropy.
    # 2 = Entropy on section high.
    # 3 = Packed.
    # 4 = Atypical SizeOfHeaders.
    # 5 = Very small section alignment.
    # 6 = Unusual ImageBase values. 
    # 7 = entry point is outside defined sections.
    # 8 = Invalid or Unusual TimeDateStamp.
    # 9 = Suspicious Strings.
    # 10 = Import suspicious of Dlls.
    # 11 = High file entropy.
    # 12 = Ips.
    # 13 = Urls.

    if checker_flags.get(3, False) and checker_flags.get(9, False):
        initial_score += 20

    elif    checker_flags.get(3, False) and (checker_flags.get(11, True) or checker_flags.get(2, True)):
        initial_score += 20

    if checker_flags.get(3, False) and checker_flags.get(9, False) and checker_flags.get(10, False):
        initial_score += 20

    if  checker_flags.get(9, False) and checker_flags.get(10, False):
        initial_score += 20

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
            
        section_scores = []
        for section in pe.sections:

            name = section.Name.decode(errors="ignore").strip().lower()
        # 2.Calculate entropy score for each section.
            entropy_score = calculate_entropy(section.get_data())
            section_scores.append(entropy_score)
            if entropy_score > 15:
                checker_flags[2] = True

        # 3.Packed files often rename sections to known packer names like UPX, etc.
        try:
            matches = yara_rules_packed.match(file_path)
                    
            if matches:
                score += 10 * len(matches)  # Increase score if suspicious packing detected
                checker_flags[3] = True  # Set packing flag
        except Exception as e:
            print(f"YARA packed matching failed for file in {file_path}: {e}")


        # 4.Atypical SizeOfHeaders may indicate attempts to evade analysis
        if not (0x200 <= pe.OPTIONAL_HEADER.SizeOfHeaders <= 0x1000):
            score += 10
            checker_flags[4] = True      

        # 5.Very small section alignment can suggest an improperly structured or obfuscated binary
        if pe.OPTIONAL_HEADER.SectionAlignment < 0x200:
            score += 10
            checker_flags[5] = True
        
        # 6.Unusual ImageBase values can indicate obfuscation or unusual execution environments
        if not (0x00400000 <= pe.OPTIONAL_HEADER.ImageBase <= 0x7FFFFFFF):
            score += 8.4
            checker_flags[6] = True
        
        # 7.If the entry point is outside defined sections, it could indicate shellcode or obfuscation
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_in_section = any(
            section.VirtualAddress <= ep < (section.VirtualAddress + section.Misc_VirtualSize)
            for section in pe.sections
        )
        if not entry_point_in_section:
            score += 7
            checker_flags[7] = True

        # 8.Invalid or Unusual TimeDateStamp
        timestamp = pe.FILE_HEADER.TimeDateStamp
        build_time = datetime.datetime.utcfromtimestamp(timestamp)
        if build_time.year < 2000:
            score += 9.8
            checker_flags[8] = True

        # 9.Suspicious strings with YARA
        try:
            matches = yara_rules_strings.match(file_path)
                    
            if matches:
                score += 9 * len(matches) # Increase score if suspicious strings detected
                checker_flags[9] = True  # Set strings flag
        except Exception as e:
            print(f"YARA suspicious string matching failed for file in {file_path}: {e}")

        # 10.Suspicious Dlls import with YARA
        try:
            matches = yara_rules_dlls.match(file_path)
                    
            if matches:
                score += 10 * len(matches) # Increase score if suspicious DLLs detected
                checker_flags[10] = True  # Set DLLs flag
        except Exception as e:
            print(f"YARA suspicious string matching failed for file in {file_path}: {e}")

         # 12.Suspicious ip with YARA
        try:
            matches = yara_rules_dlls.match(file_path)
                    
            if matches:
                score += 6  # Increase score if suspicious Ip detected
                checker_flags[12] = True  # Set Ip flag
        except Exception as e:
            print(f"YARA suspicious ip matching failed for file in {file_path}: {e}")

        # 13.Suspicious url with YARA
        try:
            matches = yara_rules_dlls.match(file_path)
                    
            if matches:
                score += 6  # Increase score if suspicious url detected
                checker_flags[13] = True  # Set url flag
        except Exception as e:
            print(f"YARA url ip matching failed for file in {file_path}: {e}")

        score = pattern_match_file_header(checker_flags, score)

        ##############SCORING##########
        if score > 47:                 # Sweet spot
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
    benign_count = 0
    malign_count = 0
    
    # Record the start time
    start_time = time.time()
    
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):  # Process all files regardless of extension
            print(f"Analyzing {file_name}...")
            result = analyze_pe(file_path)
            if result is not None:
                status, score = result
                results.append((file_name, status, score))
                if status == 'BENIGN':
                    benign_count += 1
                elif status == 'MALIGN':
                    malign_count += 1
    
    # Record the end time
    end_time = time.time()
    duration = end_time - start_time
    minutes = int(duration // 60)
    seconds = int(duration % 60)
    
    print(f"\nTotal time taken: {minutes} minutes and {seconds} seconds")
    
    # Save the results to the output file
    with open(output_file, "w") as f:
        for file_name, status, score in results:
            f.write(f"{file_name}: {status} {score:.2f}\n")
        
        # Write summary
        f.write("\nSummary:\n")
        f.write(f"Total Files: {benign_count + malign_count}\n")
        f.write(f"BENIGN: {benign_count}\n")
        f.write(f"MALIGN: {malign_count}\n")

    print(f"Results saved to {output_file}")

folder_path = "exe"  # Change this to your folder path
output_file = "pe_analysis_results.txt"   # Change this to your txt path
analyze_folder(folder_path, output_file)
