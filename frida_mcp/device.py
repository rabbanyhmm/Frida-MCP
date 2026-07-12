# Frida Device and Process Management Wrapper

import frida
from typing import Dict, List, Optional, Any

_adb_forward_proc = None

def get_adb_path() -> str:
    import shutil
    import os
    # Try bluestacks first if it exists
    bs_adb = "C:\\Program Files\\BlueStacks_nxt\\HD-Adb.exe"
    if os.path.exists(bs_adb):
        return bs_adb
    
    # Try system adb
    system_adb = shutil.which("adb")
    if system_adb:
        return system_adb
        
    return "adb"

def setup_adb_forwarding():
    """Ensure port 27042 is forwarded persistently using Popen on an isolated port."""
    global _adb_forward_proc
    if _adb_forward_proc is not None:
        if _adb_forward_proc.poll() is None:
            return  # Forwarding process is already active and running
            
    import subprocess
    import os
    import time
    env = os.environ.copy()
    env["ANDROID_ADB_SERVER_PORT"] = "5038"
    adb = get_adb_path()
    try:
        _adb_forward_proc = subprocess.Popen(
            [adb, "forward", "tcp:27042", "tcp:27042"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)  # Wait for daemon socket bind to complete
    except Exception:
        pass

def get_target_device(device_id: Optional[str] = None) -> frida.core.Device:
    """Resolve the device matching device_id, fallback to USB."""
    if device_id:
        try:
            return frida.get_device(device_id)
        except frida.InvalidArgumentError:
            # Check if matching socket connection
            if ":" in device_id:
                try:
                    return frida.get_device_manager().add_remote_device(device_id)
                except Exception:
                    pass
            raise ValueError(f"Frida device '{device_id}' not found.")
    
    # Auto-configure ADB port forwarding first
    setup_adb_forwarding()

    try:
        # Explicit remote socket connection check first for local Android Emulator bridge
        return frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    except Exception:
        try:
            return frida.get_usb_device()
        except Exception:
            raise ValueError("Could not connect to USB device or remote socket at 127.0.0.1:27042. Ensure frida-server is running.")


def enumerate_devices() -> List[Dict[str, Any]]:
    """List all available devices connected to the system."""
    return [
        {"id": d.id, "name": d.name, "type": d.type}
        for d in frida.enumerate_devices()
    ]

def list_running_processes(device_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all active processes running on the specified device."""
    dev = get_target_device(device_id)
    return [{"pid": p.pid, "name": p.name} for p in dev.enumerate_processes()]

def enumerate_applications(device_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all installed applications on the specified device (Android/iOS)."""
    dev = get_target_device(device_id)
    apps = []
    try:
        for app in dev.enumerate_applications():
            apps.append({
                "identifier": app.identifier,
                "name": app.name,
                "pid": app.pid,
                "parameters": app.parameters
            })
    except Exception:
        # Local system devices may not support this API
        pass
    return apps

def find_process_pid(name: str, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Find a running process by name or partial substring match."""
    dev = get_target_device(device_id)
    query = name.lower()
    for p in dev.enumerate_processes():
        if query in p.name.lower():
            return {"pid": p.pid, "name": p.name, "found": True}
    return {"found": False, "error": f"No running process contains the name '{name}'."}

def spawn_process(program: str, args: Optional[List[str]] = None, device_id: Optional[str] = None) -> int:
    """Spawns a program or app and returns its process ID (PID)."""
    dev = get_target_device(device_id)
    return dev.spawn(program, args=args or [])

def resume_process(pid: int, device_id: Optional[str] = None) -> None:
    """Resumes execution of a spawned or suspended process."""
    dev = get_target_device(device_id)
    dev.resume(pid)

def kill_process(pid: int, device_id: Optional[str] = None) -> None:
    """Kills a process by process ID (PID)."""
    dev = get_target_device(device_id)
    dev.kill(pid)


def suspend_process(pid: int, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Suspends/Pauses target process execution via SIGSTOP using ADB."""
    import subprocess
    adb_path = get_adb_path()
    cmd = [adb_path, "shell", f"su -c 'kill -STOP {pid}'"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        # Verify if successful or try alternative signal kill -19
        if res.returncode != 0:
            cmd_alt = [adb_path, "shell", f"su -c 'kill -19 {pid}'"]
            res = subprocess.run(cmd_alt, capture_output=True, text=True, timeout=5)
        return {"status": "success", "message": f"Sent STOP signal to PID {pid}.", "code": res.returncode}
    except Exception as e:
        return {"status": "error", "message": f"Failed to pause process via ADB: {str(e)}"}


def pull_file(remote_path: str, local_path: str) -> Dict[str, Any]:
    """Pull a file from the target device to the host."""
    import subprocess
    adb_path = get_adb_path()
    # Using su -c to copy to a readable temp location first might be needed if restricted,
    # but let's try direct pull first.
    cmd = [adb_path, "pull", remote_path, local_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode == 0:
            return {"status": "success", "message": "File pulled successfully.", "output": res.stdout}
        else:
            return {"status": "error", "message": f"ADB Pull failed: {res.stderr}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def push_file(local_path: str, remote_path: str) -> Dict[str, Any]:
    """Push a file from the host to the target device."""
    import subprocess
    adb_path = get_adb_path()
    cmd = [adb_path, "push", local_path, remote_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode == 0:
            return {"status": "success", "message": "File pushed successfully.", "output": res.stdout}
        else:
            return {"status": "error", "message": f"ADB Push failed: {res.stderr}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def resume_process_os(pid: int, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Resumes target process execution via SIGCONT using ADB with Frida fallback."""
    import subprocess
    adb_path = get_adb_path()
    cmd = [adb_path, "shell", f"su -c 'kill -CONT {pid}'"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            cmd_alt = [adb_path, "shell", f"su -c 'kill -18 {pid}'"]
            res = subprocess.run(cmd_alt, capture_output=True, text=True, timeout=5)
    except Exception:
        pass

    # Fallback to Frida's native resume
    try:
        dev = get_target_device(device_id)
        dev.resume(pid)
    except Exception:
        pass

    return {"status": "success", "message": f"Resumed process PID {pid}."}


def get_process_status(pid: int, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve detailed status metrics for a running process from /proc/<pid>/status."""
    import subprocess
    adb_path = get_adb_path()
    cmd = [adb_path, "shell", f"su -c 'cat /proc/{pid}/status'"]
    
    status_info = {
        "PID": pid,
        "Name": "unknown",
        "State": "unknown",
        "Threads": "unknown",
        "VmPeak": "unknown",
        "VmRSS": "unknown",
        "VmSize": "unknown",
        "VmData": "unknown",
        "PPid": "unknown",
        "Uid": "unknown",
        "Gid": "unknown"
    }

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    key = parts[0].strip()
                    val = parts[1].strip()
                    if key in status_info:
                        status_info[key] = val
            return {"status": "success", "details": status_info}
        else:
            # Fallback for generic/non-adb environments
            dev = get_target_device(device_id)
            for p in dev.enumerate_processes():
                if p.pid == pid:
                    status_info["Name"] = p.name
                    status_info["State"] = "Running (frida-detected)"
                    return {"status": "success", "details": status_info}
            return {"status": "error", "message": f"Process {pid} not found."}
    except Exception as e:
        return {"status": "error", "message": f"Failed to retrieve status: {str(e)}"}

