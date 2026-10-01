"""hash_file.py - command-line tool to print or check file hashes.

"""

import argparse
import os
import sys

# Tell Python where our code lives (the "src" folder) so the import below works.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from security_toolkit.hashing import hash_file, verify_file


def main():
    # 1. Describe the options this tool accepts. argparse reads what the user typed
    #    and gives us a free --help message.
    parser = argparse.ArgumentParser(description="Print or check file hashes.")
    parser.add_argument("files", nargs="+", help="one or more files")
    parser.add_argument(
        "--algorithm",
        default="sha256",
        choices=["sha256", "sha1", "md5"],
        help="hash type (default: sha256)",
    )
    parser.add_argument(
        "--check",
        metavar="HASH",
        help="compare the file with this expected hash (use with ONE file)",
    )
    args = parser.parse_args()

    # 2. --check only makes sense for a single file.
    if args.check and len(args.files) != 1:
        print("ERROR: --check works with exactly one file")
        return 1

    problems = 0   # counts files that could not be read or did not match

    for path in args.files:
        try:
            if args.check:
                if verify_file(path, args.check, args.algorithm):
                    print(f"OK: {path} matches the expected hash")
                else:
                    print(f"MISMATCH: {path} does NOT match the expected hash")
                    problems += 1
            else:
                print(f"{hash_file(path, args.algorithm)}  {path}")
        except OSError as error:
            print(f"ERROR: cannot read {path} ({error.strerror})")
            problems += 1
    if problems > 0:
        return 1
    return 0


# Runs only when you start this file directly, not when it is imported.
if __name__ == "__main__":
    sys.exit(main())
