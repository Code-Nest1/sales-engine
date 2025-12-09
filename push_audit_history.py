#!/usr/bin/env python3
import subprocess
import sys

try:
    # Stage all changes
    subprocess.run(["git", "add", "-A"], check=True, cwd="/workspaces/sales-engine")
    
    # Commit changes
    subprocess.run(
        ["git", "commit", "-m", "Add audit history for users with persistent PDF storage and downloads"],
        check=True,
        cwd="/workspaces/sales-engine"
    )
    
    # Push to main branch
    subprocess.run(["git", "push", "origin", "main"], check=True, cwd="/workspaces/sales-engine")
    
    print("✓ Changes pushed successfully!")
    
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")
    sys.exit(1)
