"""
reset.py
--------
Utility script to wipe all runtime-generated files and start fresh.

Deletes:
  - storage/encrypted_data/    all .enc files
  - storage/shared_records/    all .enc shared files
  - storage/signatures/        all .sig files
  - storage/audit_logs/        audit.log
  - storage/file_registry.json
  - keys/private/              all .pem files
  - keys/public/               all .pem files
  - keys/hmac.key
  - keys/file_registry_hmac.key
  - config/lockout.json

Keeps:
  - config/users.json          (credentials -- regenerating hashes takes time)
  - all Python source files
  - all test files

Usage:
    python reset.py
    python reset.py --yes      (skip confirmation prompt)
"""

import os
import sys
import argparse

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
DIM    = "\033[2m"

BASE = os.path.dirname(os.path.abspath(__file__))

# (label, path, type)  type = "file" | "dir_contents"
TARGETS = [
    ("Encrypted data files",  os.path.join(BASE, "storage", "encrypted_data"), "dir_contents"),
    ("Shared record files",   os.path.join(BASE, "storage", "shared_records"), "dir_contents"),
    ("Signature files",       os.path.join(BASE, "storage", "signatures"),      "dir_contents"),
    ("Audit log",             os.path.join(BASE, "storage", "audit_logs", "audit.log"), "file"),
    ("File hash registry",    os.path.join(BASE, "storage", "file_registry.json"), "file"),
    ("RSA private keys",      os.path.join(BASE, "keys", "private"),             "dir_contents"),
    ("RSA public keys",       os.path.join(BASE, "keys", "public"),              "dir_contents"),
    ("HMAC key",              os.path.join(BASE, "keys", "hmac.key"),            "file"),
    ("Registry HMAC key",     os.path.join(BASE, "keys", "file_registry_hmac.key"), "file"),
    ("Lockout state",         os.path.join(BASE, "config", "lockout.json"),      "file"),
]


def count_targets() -> int:
    total = 0
    for _, path, kind in TARGETS:
        if kind == "file":
            if os.path.exists(path):
                total += 1
        elif kind == "dir_contents":
            if os.path.isdir(path):
                total += len([f for f in os.listdir(path)
                               if os.path.isfile(os.path.join(path, f))])
    return total


def preview():
    print(f"\n{YELLOW}The following will be deleted:{RESET}\n")
    for label, path, kind in TARGETS:
        if kind == "file":
            exists = os.path.exists(path)
            status = f"{RED}1 file{RESET}" if exists else f"{DIM}not found{RESET}"
            print(f"  {label:<28} {status}")
        elif kind == "dir_contents":
            if os.path.isdir(path):
                files = [f for f in os.listdir(path)
                         if os.path.isfile(os.path.join(path, f))]
                count  = len(files)
                status = f"{RED}{count} file(s){RESET}" if count else f"{DIM}empty{RESET}"
            else:
                status = f"{DIM}not found{RESET}"
            print(f"  {label:<28} {status}")
    print()


def do_reset():
    deleted = 0
    for label, path, kind in TARGETS:
        if kind == "file":
            if os.path.exists(path):
                os.remove(path)
                print(f"  {GREEN}[DEL]{RESET} {os.path.relpath(path, BASE)}")
                deleted += 1
            else:
                print(f"  {DIM}[SKIP]{RESET} {os.path.relpath(path, BASE)} (not found)")

        elif kind == "dir_contents":
            if os.path.isdir(path):
                files = [f for f in os.listdir(path)
                         if os.path.isfile(os.path.join(path, f))]
                for f in files:
                    full = os.path.join(path, f)
                    os.remove(full)
                    print(f"  {GREEN}[DEL]{RESET} {os.path.relpath(full, BASE)}")
                    deleted += 1
                if not files:
                    print(f"  {DIM}[SKIP]{RESET} {os.path.relpath(path, BASE)}/ (empty)")
            else:
                print(f"  {DIM}[SKIP]{RESET} {os.path.relpath(path, BASE)}/ (not found)")

    return deleted


def main():
    parser = argparse.ArgumentParser(description="Reset cryptosystem runtime files.")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip confirmation prompt and delete immediately.")
    args = parser.parse_args()

    print(f"\n{YELLOW}{'─'*50}{RESET}")
    print(f"{YELLOW}  Cryptosystem Reset Utility{RESET}")
    print(f"{YELLOW}{'─'*50}{RESET}")

    total = count_targets()
    if total == 0:
        print(f"\n{GREEN}Nothing to delete. System is already clean.{RESET}\n")
        return

    preview()

    if not args.yes:
        confirm = input(f"Delete {total} file(s) and start fresh? [y/N]: ").strip().lower()
        if confirm != "y":
            print(f"\n{DIM}Reset cancelled.{RESET}\n")
            return

    print()
    deleted = do_reset()
    print()
    print(f"{GREEN}{'─'*50}{RESET}")
    print(f"{GREEN}  Reset complete. {deleted} file(s) deleted.{RESET}")
    print(f"{GREEN}  Run: streamlit run app.py{RESET}")
    print(f"{GREEN}{'─'*50}{RESET}\n")


if __name__ == "__main__":
    main()
