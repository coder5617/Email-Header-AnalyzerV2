"""
Test suite for Email Header Analyzer Pro v2.0
"""

import os
import sys
from pathlib import Path

# Add src directory to path for testing
test_dir = Path(__file__).parent
src_dir = test_dir.parent / "src"
sys.path.insert(0, str(src_dir))

__version__ = "2.0.0"
__test_data_dir__ = test_dir / "sample_headers"

# Test utilities
def get_sample_header(filename: str) -> str:
    """Load sample header file for testing"""
    sample_path = __test_data_dir__ / filename
    if sample_path.exists():
        return sample_path.read_text(encoding='utf-8')
    else:
        raise FileNotFoundError(f"Sample header file not found: {filename}")

def get_all_sample_headers() -> dict:
    """Get all available sample headers"""
    samples = {}
    if __test_data_dir__.exists():
        for file_path in __test_data_dir__.glob("*.txt"):
            samples[file_path.stem] = file_path.read_text(encoding='utf-8')
    return samples

__all__ = ['get_sample_header', 'get_all_sample_headers']
