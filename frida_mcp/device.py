# Frida Device and Process Management Wrapper

import frida
from typing import Dict, List, Optional, Any

def get_target_device(device_id: Optional[str] = None) -> frida.core.Device:
    """Resolve the device matching device_id, fallback to USB."""
    if device_id:
        try:
            return frida.get_device(device_id)
        except frida.InvalidArgumentError:
            raise ValueError(f"Frida device '{device_id}' not found.")
    try:
        return frida.get_usb_device()
    except frida.InvalidArgumentError:
        raise ValueError("No USB device connected or detected.")

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
