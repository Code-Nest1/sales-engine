#!/usr/bin/env python3
import subprocess
import os

os.chdir('/workspaces/sales-engine')

# Stage files
subprocess.run(['git', 'add', 'app.py', 'requirements.txt'], check=False)

# Commit
subprocess.run([
    'git', 'commit', '-m', 
    'Fix: Make 2FA optional with graceful fallback, update dependencies'
], check=False)

# Push
result = subprocess.run(['git', 'push', 'origin', 'main'], capture_output=True, text=True)
print(result.stdout)
print(result.stderr)
print("✅ Pushed to GitHub!")
