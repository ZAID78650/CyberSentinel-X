#!/bin/bash
# Kill old vite processes
lsof -ti:5173 2>/dev/null | xargs kill -9 2>/dev/null
lsof -ti:5174 2>/dev/null | xargs kill -9 2>/dev/null
sleep 1

# Start vite in background
cd /Users/zaidshaikhmohammad/Desktop/cybersentinel-x/frontend
node node_modules/.bin/vite --host --port 5173 &
VITE_PID=$!

sleep 4

# Test
echo "Vite PID: $VITE_PID"
curl -s -m 3 http://localhost:5173/ | head -20 || echo "No response"

# Keep running
wait $VITE_PID
