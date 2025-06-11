import yara
import os
import sys

def load_rules(rule_path):
    try:
        return yara.compile(filepath=rule_path)
    except yara.Error as e:
        print(f"[!] Failed to compile YARA rules: {e}")
        sys.exit(1)

def offset_to_line_number(file_path, offset):
    """Convert byte offset to line number, handling encoding carefully."""
    try:
        with open(file_path, 'rb') as f:
            content = f.read(offset)
            return content.count(b'\n') + 1
    except Exception as e:
        print(f"[!] Error reading file for offset calculation: {e}")
        return 1

def scan_file(file_path, rules):
    try:
        matches = rules.match(file_path)
        if not matches:
            return

        print(f"[*] Scanning: {file_path}")
        
        # Read file content for line display
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[!] Could not read file content: {e}")
            lines = []

        for match in matches:
            print(f"  🔸 Rule: {match.rule}")
            for s in match.strings:
                string_id = s.identifier
                for instance in s.instances:
                    offset = instance.offset
                    line_num = offset_to_line_number(file_path, offset)
                    
                    # Get line content safely
                    if lines and line_num <= len(lines):
                        line_text = lines[line_num - 1].strip()
                        # Truncate very long lines for readability
                        if len(line_text) > 200:
                            line_text = line_text[:200] + "..."
                    else:
                        line_text = '[Line not found]'
                    
                    print(f"    ↪ Match: {string_id} at line {line_num}: {line_text}")
    except Exception as e:
        print(f"[!] Error scanning {file_path}: {e}")

def scan_directory(directory, rules, extensions=('.php', '.js')):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(extensions):
                full_path = os.path.join(root, file)
                scan_file(full_path, rules)

def main():
    print(f"[*] Using yara-python version: {yara.__version__}")

    if len(sys.argv) != 3:
        print("Usage: python yara_line_matcher.py <rules.yar> <target_file_or_directory>")
        sys.exit(1)

    yara_file = sys.argv[1]
    target = sys.argv[2]

    if not os.path.exists(yara_file):
        print(f"[!] YARA rule file not found: {yara_file}")
        sys.exit(1)
    if not os.path.exists(target):
        print(f"[!] Target file/directory does not exist: {target}")
        sys.exit(1)

    print("[*] Compiling YARA rules...")
    rules = load_rules(yara_file)

    if os.path.isfile(target):
        print(f"[*] Scanning file: {target}")
        scan_file(target, rules)
    elif os.path.isdir(target):
        print(f"[*] Scanning directory: {target}")
        scan_directory(target, rules)
    else:
        print(f"[!] Target is neither a file nor a directory: {target}")
        sys.exit(1)

if __name__ == "__main__":
    main()