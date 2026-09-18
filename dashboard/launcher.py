import threading
import time
import webbrowser
import sys
import os
import uvicorn

from app import app

HOST = "127.0.0.1"
PORT = 8000

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

def open_browser():
    # give uvicorn a moment to actually start listening before we try to load the page
    time.sleep(1.5)
    webbrowser.open(f"http://{HOST}:{PORT}")


if __name__ == "__main__":
    print("Starting Agentic Security Dashboard...")
    print(f"Opening http://{HOST}:{PORT} in your browser...")

    threading.Thread(target=open_browser, daemon=True).start()

    # no --reload here on purpose: the reloader spawns a watcher subprocess
    # and re-imports app.py on file changes, which doesn't behave once this
    # is frozen into a single .exe (there are no source files to watch)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")