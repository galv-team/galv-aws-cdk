import os
import shutil
import sys
from pathlib import Path

"""
This script is a workaround for the issue where the Node.js binary is not found in the PATH
when running tests on Linux. This is due to the fact that the nvm-managed Node.js binary is
not available in the PATH when running tests in a subprocess.
"""

def get_nvm_node_bin():
    nvm_versions_dir = Path.home() / ".nvm" / "versions" / "node"
    if not nvm_versions_dir.is_dir():
        return None

    try:
        # Check for 'default' alias if present
        default_alias = Path.home() / ".nvm" / "alias" / "default"
        if default_alias.exists():
            with default_alias.open() as f:
                default_version = f.read().strip()
                bin_path = nvm_versions_dir / default_version / "bin"
                if bin_path.is_dir():
                    return str(bin_path)

        # Fallback: pick the highest semver-looking directory
        versions = sorted(
            (d for d in nvm_versions_dir.iterdir() if d.is_dir()),
            key=lambda d: [int(x) for x in d.name.strip("v").split(".")],
            reverse=True
        )
        if versions:
            return str(versions[0] / "bin")
    except Exception as e:
        print(f"Failed to resolve nvm node path: {e}")
        return None

def hack_nvm_path():
    if sys.platform.startswith("linux") and shutil.which("node") is None:
        node_bin_path = get_nvm_node_bin()
        if node_bin_path and os.path.isdir(node_bin_path):
            os.environ["PATH"] = f"{node_bin_path}:{os.environ['PATH']}"
            print("Updated PATH to include Node.js from nvm.")
            print("Node path now:", shutil.which("node"))
        else:
            print("Warning: Could not locate Node.js via nvm.")
