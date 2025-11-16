import subprocess
import sys

# Run backend
subprocess.Popen([sys.executable, "app.py"])

# Run frontend
subprocess.Popen([sys.executable, "gui.py"])

# Keep script running (important!)
while True:
    pass