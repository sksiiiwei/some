#!/usr/bin/env python3
"""
Universal Safe Pickle Analysis Tool
Detects malicious code execution, suspicious imports, and patterns in pickle files.
Supports single files, directories, and JSON output for CI/CD integration.
usage:
  python safe_analysis_pkl.py /opt/supply-chain/models/ (or file *.pkl)
  python safe_analysis_pkl.py model.pkl --json | jq .
"""

import pickletools
import argparse
import os
import json
from pathlib import Path

# Расширенный список опасных модулей (включая системные псевдонимы)
DANGEROUS_MODULES = {
    "os", "subprocess", "sys", "socket", "shutil", "ctypes", 
    "builtins", "importlib", "code", "codeop", "pty", "posix", 
    "nt", "mac", "runpy", "shlex"
}

# Расширенный список опасных функций
DANGEROUS_FUNCTIONS = {
    "system", "popen", "exec", "eval", "execfile", 
    "call", "Popen", "check_output", "run", 
    "getattr", "setattr", "delattr", "__import__",
    "spawn", "fork", "pty"
}

# Расширенные подозрительные паттерны (сеть, шеллы, файлы)
SUSPICIOUS_PATTERNS =[
    "http://", "https://", "ftp://", "curl ", "wget ", 
    "/etc/passwd", "/etc/shadow", "/tmp/", "$(", "`", 
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "nc -"
]

# Все опкоды pickle, которые могут загружать строки/байты
STRING_OPCODES = {
    "STRING", "BINSTRING", "SHORT_BINSTRING", 
    "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", 
    "BINBYTES", "SHORT_BINBYTES", "BINBYTES8"
}

def format_size(size_bytes):
    """Возвращает человекочитаемый размер файла."""
    if size_bytes >= 1_000_000_000:
        return f"{size_bytes / 1_000_000_000:.2f} GB"
    elif size_bytes >= 1_000_000:
        return f"{size_bytes / 1_000_000:.2f} MB"
    elif size_bytes >= 1000:
        return f"{size_bytes / 1000:.2f} KB"
    return f"{size_bytes} bytes"

def analyze_pickle_data(filepath):
    """
    Парсит pickle и возвращает словарь с результатами анализа.
    Не привязан к формату вывода (полезно для API).
    """
    path = Path(filepath)
    result = {
        "file": str(path),
        "size_bytes": path.stat().st_size,
        "size_human": format_size(path.stat().st_size),
        "status": "SAFE",
        "errors": None,
        "findings": {
            "dangerous_imports": [],
            "suspicious_strings":[],
            "exec_calls": 0
        }
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
            ops = list(pickletools.genops(data))
    except Exception as e:
        result["status"] = "ERROR"
        result["errors"] = f"Failed to parse pickle: {str(e)}"
        return result

    recent_strings =[]  # Отслеживание последних загруженных строк для STACK_GLOBAL
    imports_found =[]

    for opcode, arg, pos in ops:
        name = opcode.name

        # 1. Отслеживание строк и байтов
        if name in STRING_OPCODES:
            val = arg.decode('utf-8', errors='ignore') if isinstance(arg, bytes) else str(arg)
            recent_strings.append(val)
            
            # Сохраняем только последние 2 строки (обычно это модуль и функция)
            if len(recent_strings) > 2:
                recent_strings.pop(0)

            # Проверка на подозрительные паттерны
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in val and val not in result["findings"]["suspicious_strings"]:
                    result["findings"]["suspicious_strings"].append(val)

        # 2. Обнаружение импортов (Протоколы 0-3: GLOBAL)
        elif name == "GLOBAL":
            if isinstance(arg, str) and " " in arg:
                mod, func = arg.split(" ", 1)
                imports_found.append((mod, func))

        # 3. Обнаружение импортов (Протоколы 4+: STACK_GLOBAL)
        elif name == "STACK_GLOBAL":
            if len(recent_strings) >= 2:
                mod, func = recent_strings[0], recent_strings[1]
                imports_found.append((mod, func))
            
            # Очищаем стек строк после использования
            recent_strings.clear()

        # 4. Обнаружение выполнения функций (REDUCE)
        elif name == "REDUCE":
            result["findings"]["exec_calls"] += 1

    # Анализ найденных импортов
    for mod, func in imports_found:
        if mod in DANGEROUS_MODULES or func in DANGEROUS_FUNCTIONS:
            threat = f"{mod}.{func}"
            if threat not in result["findings"]["dangerous_imports"]:
                result["findings"]["dangerous_imports"].append(threat)

    # Вынесение вердикта
    if result["findings"]["dangerous_imports"] or result["findings"]["suspicious_strings"]:
        result["status"] = "UNSAFE"

    return result

def print_text_report(report):
    """Выводит отчет в удобочитаемом текстовом формате."""
    print(f"{'='*40}")
    print(f"File: {report['file']}")
    print(f"Size: {report['size_human']}")
    
    if report["status"] == "ERROR":
        print(f"\n[!] ERROR: {report['errors']}")
        print(f"{'='*40}\n")
        return

    findings = report["findings"]
    
    if findings["dangerous_imports"]:
        print("\n[CRITICAL] Dangerous imports/opcodes found:")
        for imp in findings["dangerous_imports"]:
            print(f"  - IMPORT/EXECUTE: {imp}")

    if findings["suspicious_strings"]:
        print("\n[CRITICAL] Suspicious strings/payloads detected:")
        for s in findings["suspicious_strings"]:
            print(f"  - '{s}'")

    if report["status"] == "UNSAFE":
        # Динамическое формирование причины для вердикта
        targets = [imp for imp in findings["dangerous_imports"]]
        target_str = targets[0] if targets else "unknown execution"
        print(f"\nVerdict: UNSAFE - Contains executable code targeting '{target_str}'")
    else:
        print("\nVerdict: SAFE - No executable code detected")
    print(f"{'='*40}\n")

def main():
    parser = argparse.ArgumentParser(description="Universal Safe Pickle Analysis Tool")
    parser.add_argument("path", help="Path to a .pkl file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)

    # Собираем файлы для анализа
    files_to_scan =[]
    if target_path.is_file():
        files_to_scan.append(target_path)
    elif target_path.is_dir():
        for ext in ("*.pkl", "*.pickle", "*.pt", "*.pth"): # поддержка PyTorch форматов
            files_to_scan.extend(target_path.rglob(ext))

    if not files_to_scan:
        print("No pickle files found to analyze.")
        sys.exit(0)

    results =[]
    for file in files_to_scan:
        report = analyze_pickle_data(file)
        results.append(report)

    # Вывод результатов
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for report in results:
            print_text_report(report)
        
        # Общая статистика для директорий
        if len(files_to_scan) > 1:
            unsafe_count = sum(1 for r in results if r["status"] == "UNSAFE")
            print(f"Scanned {len(files_to_scan)} files. Found {unsafe_count} UNSAFE files.")

    # Возвращаем код ошибки, если есть опасные файлы (полезно для CI/CD)
    if any(r["status"] == "UNSAFE" for r in results):
        sys.exit(1)

if __name__ == "__main__":
    import sys # импортируется здесь, чтобы не засорять глобальное пространство
    main()
