import os
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

os.environ.setdefault("SECRET_KEY", "pytest-test-key")
