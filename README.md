# 🛡️ WordPress YARA Ruleset

This repository contains a curated set of [YARA](https://virustotal.github.io/yara/) rules designed to detect common malware patterns, obfuscated code, database issues, and webshell activity in WordPress installations.

---

## 📁 Contents

- `wordpress-threats.yar` – Detects webshells, suspicious PHP functions, obfuscated strings, and malicious uploads.
- `wp-db-issues.yar` – Flags unsafe database access patterns like unprepared queries or user input concatenation.
- `test-payloads/` – Optional directory for known malicious or suspicious code snippets to test rule effectiveness.
- `yara_line_matcher.py` – Python script to automate recursive scans and print match context with line number sample command.
- `python3 yara_line_matcher.py rules/wordpress-threats.yar ../wordpress-plugin-path/  --skip-folders node_modules,vendor,.git,js`
---

## 🚀 Getting Started

### 📦 Requirements
# Linux:
- YARA (v4+ recommended)
  ```bash
  sudo apt install yara

# Windows:
- YARA (Run powershell as admin):
  ``` 
  choco install yara
- Python package:
  ```
  pip install yara-python
  