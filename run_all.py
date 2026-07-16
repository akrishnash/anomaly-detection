import os
import sys
import subprocess
import time
import webbrowser
import threading
import signal

def kill_process_tree(process):
    """Kills a process and all of its child processes."""
    if not process:
        return
    
    pid = process.pid
    print(f"[*] Stopping process tree with PID {pid}...")
    if sys.platform == "win32":
        # On Windows, taskkill is needed to kill the shell and all its child processes
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        except Exception as e:
            print(f"[-] Failed to taskkill PID {pid}: {e}")
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                process.terminate()
            except Exception:
                pass

def log_stream(stream, prefix):
    """Reads a stream line by line and prints it with a prefix."""
    try:
        for line in iter(stream.readline, ""):
            if not line:
                break
            print(f"{prefix} {line.strip()}")
    except Exception:
        pass

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.join(root_dir, "project", "frontend")
    backend_script = os.path.join(root_dir, "project", "backend", "main.py")
    
    print("=" * 60)
    print("      Aegis-IDS Startup Orchestrator")
    print("=" * 60)
    
    # 1. Ensure Frontend Node Modules are Installed
    node_modules_dir = os.path.join(frontend_dir, "node_modules")
    if not os.path.exists(node_modules_dir):
        print("[*] Frontend node_modules not found. Installing package dependencies...")
        print("[*] Running 'npm install' in project/frontend/ ...")
        try:
            # Run npm install synchronously and wait for it to complete
            subprocess.run("npm install", shell=True, cwd=frontend_dir, check=True)
            print("[+] Frontend dependencies installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[-] 'npm install' failed with exit code {e.returncode}. Please install Node.js and run 'npm install' manually.")
            sys.exit(1)
    else:
        print("[+] Frontend dependencies already installed.")

    # 2. Start Backend FastAPI Server
    print("[*] Starting FastAPI Backend...")
    # Use sys.executable to ensure we run under the same environment that has dependencies
    backend_proc = subprocess.Popen(
        [sys.executable, "-u", backend_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=root_dir
    )
    
    # 3. Start Frontend Vite Dev Server
    print("[*] Starting React Frontend (Vite)...")
    frontend_proc = subprocess.Popen(
        "npm run dev",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=frontend_dir
    )
    
    # Start stdout/stderr forwarding threads
    backend_thread = threading.Thread(target=log_stream, args=(backend_proc.stdout, "[Backend]"), daemon=True)
    frontend_thread = threading.Thread(target=log_stream, args=(frontend_proc.stdout, "[Frontend]"), daemon=True)
    
    backend_thread.start()
    frontend_thread.start()
    
    # Give servers a few seconds to boot, then open browser
    time.sleep(4)
    print("\n[+] Both servers launched. Opening browser at http://localhost:3000...")
    webbrowser.open("http://localhost:3000")
    
    print("\n[*] Orchestrator is running. Press Ctrl+C to stop both servers gracefully.\n")
    
    try:
        # Keep orchestrator alive while processes are running
        while True:
            # Check if any process has exited unexpectedly
            backend_exit = backend_proc.poll()
            frontend_exit = frontend_proc.poll()
            
            if backend_exit is not None:
                print(f"\n[-] Backend server exited unexpectedly with code {backend_exit}.")
                break
            if frontend_exit is not None:
                print(f"\n[-] Frontend server exited unexpectedly with code {frontend_exit}.")
                break
                
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt received. Shutting down servers...")
    finally:
        # Clean up processes
        print("[*] Terminating processes...")
        kill_process_tree(backend_proc)
        kill_process_tree(frontend_proc)
        print("[+] Cleanup complete. Goodbye!")

if __name__ == "__main__":
    main()
