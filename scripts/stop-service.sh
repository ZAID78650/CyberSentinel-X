#!/bin/bash
# Stop CyberSentinel X launchd services
LA="$HOME/Library/LaunchAgents"
launchctl unload "$LA/com.cybersentinel.backend.plist" 2>/dev/null && echo "[stop] backend stopped" || echo "[stop] backend not loaded"
launchctl unload "$LA/com.cybersentinel.frontend.plist" 2>/dev/null && echo "[stop] frontend stopped" || echo "[stop] frontend not loaded"
echo "[stop] done"
