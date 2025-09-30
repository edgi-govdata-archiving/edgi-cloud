#!/usr/bin/env python3
# add the current directory to the path so we can import password_generator
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from password_generator import generate_password

if __name__ == "__main__":
    print(generate_password())
