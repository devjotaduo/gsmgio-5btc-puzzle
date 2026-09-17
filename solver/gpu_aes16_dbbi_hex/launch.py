# -*- coding: utf-8 -*-
"""Lança a varredura completa (scan_full.py) em segundo plano, processo separado,
stdout/stderr para scan.log. Imprime o PID. Retoma do checkpoint.json se existir."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = r"C:\Users\ruthe\AppData\Local\Programs\Python\Python312\python.exe"
LOG = os.path.join(HERE, "scan.log")


def main():
    logf = open(LOG, "a", encoding="utf-8")
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS
    p = subprocess.Popen([PY, os.path.join(HERE, "scan_full.py")],
                         stdout=logf, stderr=subprocess.STDOUT,
                         cwd=HERE, creationflags=flags, close_fds=True)
    print("PID", p.pid, "log", LOG)


if __name__ == "__main__":
    main()
