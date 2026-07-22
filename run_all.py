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

def wait_for_backend(port, proc, timeout=120):
    """Polls the backend until it answers, so the frontend isn't launched into a
    dead upstream. The backend's startup_event loads/trains the ML models, which
    takes several seconds; if the frontend starts first its /api polls fail with
    ECONNREFUSED and the browser shows a wall of 502s. Returns True once the
    backend responds, False if it exits first or the timeout elapses."""
    import urllib.request
    import urllib.error
    url = f"http://127.0.0.1:{port}/api/online/status"
    deadline = time.time() + timeout
    print(f"[*] Waiting for backend to become ready at {url} ...")
    while time.time() < deadline:
        if proc.poll() is not None:
            print(f"[-] Backend exited (code {proc.returncode}) before it became ready.")
            return False
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status < 500:
                    print("[+] Backend is ready.")
                    return True
        except urllib.error.HTTPError:
            # Any HTTP response (even 4xx) means the server is up and serving.
            print("[+] Backend is ready.")
            return True
        except Exception:
            pass  # Not up yet (connection refused / in flight) -- keep polling.
        time.sleep(0.5)
    print(f"[-] Backend did not become ready within {timeout}s.")
    return False

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

    # 2. Pick a free backend port (default 8000; falls forward if another app,
    # e.g. a stale VS Code port-forward, is holding it) and share it with both
    # the backend and the Vite dev-server proxy via AEGIS_BACKEND_PORT.
    import socket
    backend_port = None
    preferred = int(os.environ.get("AEGIS_BACKEND_PORT", 8000))
    for p in range(preferred, preferred + 11):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
            backend_port = p
            break
        except OSError:
            print(f"[!] Port {p} is busy or blocked (another app may be holding it), trying {p + 1}...")
    if backend_port is None:
        print(f"[-] No free backend port found in range {preferred}-{preferred + 10}. Aborting.")
        sys.exit(1)
    if backend_port != preferred:
        print(f"[!] Default port {preferred} unavailable -> backend will run on {backend_port} instead.")
    child_env = {**os.environ, "AEGIS_BACKEND_PORT": str(backend_port)}

    # 3. Start Backend FastAPI Server
    print(f"[*] Starting FastAPI Backend on port {backend_port}...")
    # Use sys.executable to ensure we run under the same environment that has dependencies
    backend_proc = subprocess.Popen(
        [sys.executable, "-u", backend_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=root_dir,
        env=child_env
    )

    # Drain the backend's output immediately so its PIPE buffer can't fill and
    # block the process while we wait for it to finish booting.
    backend_thread = threading.Thread(target=log_stream, args=(backend_proc.stdout, "[Backend]"), daemon=True)
    backend_thread.start()

    # 3b. Wait for the backend to actually serve requests BEFORE launching the
    # frontend. Otherwise Vite (ready in ~1s) proxies /api calls into a backend
    # that is still loading its ML models and every call 502s until it catches up.
    if not wait_for_backend(backend_port, backend_proc):
        print("[-] Backend never came up. Aborting so we don't launch a broken UI.")
        kill_process_tree(backend_proc)
        sys.exit(1)

    # 4. Pick a free frontend port too (VS Code port-forwards can squat 5173 as
    # well) and start the Vite Dev Server pinned to it.
    frontend_port = None
    for p in range(5173, 5184):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
            frontend_port = p
            break
        except OSError:
            print(f"[!] Frontend port {p} is busy or blocked, trying {p + 1}...")
    if frontend_port is None:
        print("[-] No free frontend port found in range 5173-5183. Aborting.")
        kill_process_tree(backend_proc)
        sys.exit(1)
    if frontend_port != 5173:
        print(f"[!] Default port 5173 unavailable -> frontend will run on {frontend_port} instead.")

    print(f"[*] Starting React Frontend (Vite) on port {frontend_port}...")
    frontend_proc = subprocess.Popen(
        f"npm run dev -- --port {frontend_port} --strictPort",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=frontend_dir,
        env=child_env
    )
    
    # Backend output is already being drained (thread started above); just add
    # the frontend forwarder here.
    frontend_thread = threading.Thread(target=log_stream, args=(frontend_proc.stdout, "[Frontend]"), daemon=True)
    frontend_thread.start()

    # Backend is confirmed ready; give Vite a moment to bind, then open browser.
    time.sleep(2)
    print(f"\n[+] Both servers launched. Opening browser at http://127.0.0.1:{frontend_port}...")
    webbrowser.open(f"http://127.0.0.1:{frontend_port}")
    
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
