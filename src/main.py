import pefile
import os
import math
from collections import Counter
from scipy.stats import entropy
import time
import datetime
import yara

# Load YARA rules once
yara_rules = yara.compile(filepath="Yara/packer.yar")

safe_packer_keywords = [
    "NETexecutableMicrosoft",
    "NETDLLMicrosoft",
    "Microsoft",
]

def is_safe_packer(matched_rules):
    """Check if any matched YARA rule is a safe/legal packer."""
    for rule in matched_rules:
        for keyword in safe_packer_keywords:
            if keyword.lower() in rule.lower():
                return True
    return False


def pattern_match_file_header(checker_flags, initial_score):
    # 1 = Low entropy.
    # 2 = Hihg entropy.
    # 3 = Entropy for each section high.
    # 4 = Atypical SizeOfHeaders.
    # 5 = Very small section alignment.
    # 6 = Unusual ImageBase values. 
    # 7 = entry point is outside defined sections.
    # 8 = Invalid or Unusual TimeDateStamp.

    rare_flags = [2, 3, 4, 5, 6, 7, 8]
    moderate_flags = [1]

    rare_hits = sum(1 for i in rare_flags if checker_flags.get(i, False))
    moderate_hits = sum(1 for i in moderate_flags if checker_flags.get(i, False))

    # Pattern logic
    #if rare_hits == 2:
    #    initial_score += 10
    #elif rare_hits >= 3:
    #    initial_score += 20


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
                matches = yara_rules.match(data=section.get_data())
                if matches:
                    matched_rule_names = [match.rule for match in matches]
                    
                    if not is_safe_packer(matched_rule_names):
                        score += 15  # Increase score if suspicious packing detected
                        checker_flags[3] = True  # Set packing flag
                    else:
                        score -= 10
            except Exception as e:
                print(f"YARA matching failed for section {name} in {file_path}: {e}")


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

        score = pattern_match_file_header(checker_flags, score)

        # 8.Invalid or Unusual TimeDateStamp
        timestamp = pe.FILE_HEADER.TimeDateStamp
        build_time = datetime.datetime.utcfromtimestamp(timestamp)
        if build_time.year < 2000:
            score += 9.8
            checker_flags[8] = True
        ####SCORING##########
        if score > 42:
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
output_file = "pe_analysis_results.txt"   # Change this to your txt path if not will be created
analyze_folder(folder_path, output_file)
