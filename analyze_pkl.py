#!/usr/bin/env python3
"""
Safe Pickle Analysis Tool
Structured summary of pickle file safety.

Usage: python safe_analysis.py <pickle_file>
"""

import pickletools
import sys
import os
from pathlib import Path

# Модули и функции, считающиеся опасными в файле pickle
DANGEROUS_MODULES = {"os", "subprocess", "sys", "socket", "shutil", "ctypes", 
                     "builtins", "importlib", "code", "codeop"}

DANGEROUS_FUNCTIONS = {"system", "popen", "exec", "eval", "execfile", 
                       "call", "Popen", "check_output", "run", 
                       "getattr", "setattr", "delattr", "__import__"}

SUSPICIOUS_PATTERNS = ["http://", "https://", "ftp://", "curl ", "wget ", 
                       "/etc/passwd", "/etc/shadow", "/tmp/", "$(", "`"]

def analyze_pickle(filepath):
    """Создает структурированный отчет о безопасности, ожидаемый в Room 2."""
    path = Path(filepath)
    size_bytes = path.stat().st_size
    
    # Человекочитаемый размер (в десятичных МБ для соответствия Room 2)
    if size_bytes >= 1_000_000:
        size_str = f"{size_bytes / 1_000_000:.1f} MB"
    elif size_bytes >= 1000:
        size_str = f"{size_bytes / 1000:.1f} KB"
    else:
        size_str = f"{size_bytes} bytes"

    with open(filepath, "rb") as f:
        data = f.read()

    ops = list(pickletools.genops(data))

    # Сбор результатов
    dangerous_opcodes = []
    suspicious_strings = []
    imported_modules = []
    pending_global = None # отслеживает module.function для STACK_GLOBAL

    i = 0
    while i < len(ops):
        opcode, arg, pos = ops[i]
        name = opcode.name

        # Обнаружение паттерна STACK_GLOBAL: два SHORT_BINUNICODE, затем STACK_GLOBAL
        if name in ("SHORT_BINUNICODE", "BINUNICODE") and isinstance(arg, str):
            # Проверка, является ли это импортом модуля
            if arg in DANGEROUS_MODULES:
                imported_modules.append(arg)
                # Заглядываем вперед для поиска имени функции + STACK_GLOBAL
                if i + 2 < len(ops):
                    func_idx = i + 1
                    # Пропускаем MEMOIZE между модулем и функцией
                    while func_idx < len(ops) and ops[func_idx][0].name == "MEMOIZE":
                        func_idx += 1
                    
                    if func_idx < len(ops):
                        func_op, func_arg, _ = ops[func_idx]
                        if func_op.name in ("SHORT_BINUNICODE", "BINUNICODE"):
                            # Ищем STACK_GLOBAL после имени функции
                            sg_idx = func_idx + 1
                            while sg_idx < len(ops) and ops[sg_idx][0].name == "MEMOIZE":
                                sg_idx += 1
                            
                            if sg_idx < len(ops) and ops[sg_idx][0].name == "STACK_GLOBAL":
                                pending_global = f"{arg}.{func_arg}"
                                dangerous_opcodes.append(f"STACK_GLOBAL: {arg}.{func_arg}")

            # Проверка содержимого строк на подозрительные паттерны
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in arg:
                    suspicious_strings.append(arg)
                    break

        if name == "REDUCE" and pending_global:
            dangerous_opcodes.append(
                f"REDUCE: executes {pending_global} with arguments"
            )
            pending_global = None

        i += 1

    # Вывод результатов
    print(f"=== Pickle Safety Analysis ===")
    print(f"File: {filepath}")
    print(f"Size: {size_str}")

    if dangerous_opcodes:
        print("\nDangerous opcodes found:")
        for entry in dangerous_opcodes:
            print(f"  [CRITICAL] {entry}")

    if suspicious_strings:
        print("\nSuspicious strings:")
        for s in suspicious_strings:
            print(f"  [CRITICAL] '{s}'")

    # Вердикт
    if dangerous_opcodes or suspicious_strings:
        targets = [m for m in imported_modules if m in DANGEROUS_MODULES]
        target_str = ".".join([targets[0], "system"]) if targets else "unknown"
        print(f"\nVerdict: UNSAFE - Contains executable code targeting {target_str}")
    else:
        print("\nNo dangerous opcodes or suspicious strings found.")
        print("\nVerdict: SAFE - No executable code detected")

def main():
    if len(sys.argv) < 2:
        print("Usage: python safe_analysis.py <pickle_file>")
        print("\nExamples:")
        print("  python safe_analysis.py /opt/supply-chain/models/code_reviewer.pkl")
        print("  python safe_analysis.py /opt/supply-chain/models/code_reviewer_v1.pkl")
        sys.exit(1)

    filepath = sys.argv[1]
    if not Path(filepath).exists():
        print(f"\n[!] Error: File not found: {filepath}\n")
        sys.exit(1)

    analyze_pickle(filepath)

if __name__ == "__main__":
    main()
