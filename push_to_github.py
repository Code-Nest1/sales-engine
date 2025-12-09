#!/usr/bin/env python3
import subprocess
import os

os.chdir('/workspaces/sales-engine')

# Stage files
subprocess.run(['git', 'add', 'app.py', 'requirements.txt', 'users.json', 'two_fa.json'], check=True)

# Commit
subprocess.run([
    'git', 'commit', '-m', 
    '🚀 Implement comprehensive app enhancements: 2FA authentication, dashboard with analytics, enhanced audit checks (accessibility/security), email templates library, Slack notifications, improved lead scoring (0-100 scale), admin analytics dashboard, color-coded badges, advanced filtering, mobile responsiveness, and enterprise-grade UI/UX improvements'
], check=True)

# Push
subprocess.run(['git', 'push', 'origin', 'main'], check=True)

print("✅ Successfully pushed to GitHub!")
