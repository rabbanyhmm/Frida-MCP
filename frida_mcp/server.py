# Frida MCP Server CLI Entrypoint

import frida
from mcp.server.fastmcp import FastMCP
from pydantic import Field
from typing import Dict, List, Optional, Any

from . import device
from . import memory

# Initialize the FastMCP Server
mcp = FastMCP("FridaMCP")


@mcp.tool()
def list_devices() -> List[Dict[str, Any]]:
    """List all available devices connected to the system."""
    return device.enumerate_devices()


@mcp.tool()
def list_processes(
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> List[Dict[str, Any]]:
    """List all running processes on the selected device."""
    return device.list_running_processes(device_id)


@mcp.tool()
def locate_process(
    name: str = Field(description="Sub-string of the process name to match (case-insensitive)."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Find a running process by its name or partial name."""
    return device.find_process_pid(name, device_id)


@mcp.tool()
def spawn_program(
    program: str = Field(description="Executable path or package bundle identifier to spawn."),
    arguments: Optional[List[str]] = Field(default=None, description="Optional command-line arguments."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Spawn a process for a program or app."""
    try:
        pid = device.spawn_process(program, arguments, device_id)
        return {"pid": pid, "success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def resume_process(
    pid: int = Field(description="Process ID to resume."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Resume execution of a spawned or suspended process."""
    try:
        device.resume_process(pid, device_id)
        return {"pid": pid, "success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def terminate_process(
    pid: int = Field(description="Process ID to terminate."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Forcefully kill a running process by ID."""
    try:
        device.kill_process(pid, device_id)
        return {"pid": pid, "success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# Memory Hacking / Game Guardian Tools
@mcp.tool()
def open_session(
    pid: int = Field(description="Target Process ID (PID) to attach to."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Create an interactive session on a target process, loading the memory scanning engine."""
    try:
        session_id = memory.create_memory_session(pid, device_id)
        return {
            "status": "success",
            "pid": pid,
            "session_id": session_id,
            "message": "Interactive session created with memory scanning engine loaded."
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def close_session(
    session_id: str = Field(description="Active session ID to close.")
) -> Dict[str, Any]:
    """Close an interactive session, unloading the agent and detaching from the process."""
    try:
        memory.close_memory_session(session_id)
        return {"status": "success", "session_id": session_id, "message": "Session closed."}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_search(
    session_id: str = Field(description="Active session ID."),
    value: str = Field(description="Value to search for (as a string or hex byte pattern)."),
    val_type: str = Field(description="Value type: 'byte' (1-byte int), 'word' (2-byte int), 'dword' (4-byte int), 'qword' (8-byte int), 'float', 'double', 'utf8', 'utf16', or 'hex' (raw byte pattern)."),
    regions: Optional[List[str]] = Field(default=None, description="Search regions filter list. Elements: 'anon' (Anonymous maps), 'heap' (Heap/Dalvik), 'stack' (Call stacks), 'code' (App libraries/.so/APKs)."),
    xor_key: Optional[int] = Field(default=None, description="Optional XOR encryption key to apply to values during search.")
) -> Dict[str, Any]:
    """Scan process memory for a value of a given type."""
    try:
        count = memory.search_memory(session_id, value, val_type, regions, xor_key)
        return {"status": "success", "matches_found": count}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_refine(
    session_id: str = Field(description="Active session ID."),
    value: str = Field(description="Value to compare candidates against (as a string)."),
    mode: str = Field(default="exact", description="Refine comparison mode: 'exact' (equal), 'changed' (value altered), 'unchanged' (value static), 'increased' (now larger), 'decreased' (now smaller), 'greater' (larger than value), 'less' (smaller than value).")
) -> Dict[str, Any]:
    """Filter previous search results based on updated values or relative comparisons."""
    try:
        count = memory.refine_memory(session_id, value, mode)
        return {"status": "success", "remaining_matches": count}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_pointer_search(
    session_id: str = Field(description="Active session ID."),
    limit: int = Field(default=100, description="Max pointer results to return.")
) -> Dict[str, Any]:
    """Scan memory pages to locate pointers that reference active search candidate addresses."""
    try:
        pointers = memory.search_pointers_resolving_to_candidates(session_id, limit)
        return {"status": "success", "pointers": pointers}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_group_search(
    session_id: str = Field(description="Active session ID."),
    group_str: str = Field(description="Semicolon separated list of values (e.g. '100;50;99') representing nearby values in memory."),
    max_distance: int = Field(default=100, description="Maximum address distance between group members (bytes)."),
    regions: Optional[List[str]] = Field(default=None, description="Regions filter list.")
) -> Dict[str, Any]:
    """Perform a group search for multiple numbers located close to one another."""
    try:
        count = memory.group_search_memory(session_id, group_str, max_distance, regions)
        return {"status": "success", "matches_found": count}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_get_candidates(
    session_id: str = Field(description="Active session ID."),
    limit: int = Field(default=100, description="Max candidates to read and display.")
) -> Dict[str, Any]:
    """Retrieve the current list of memory search candidate addresses and their active values."""
    try:
        return memory.get_candidates_list(session_id, limit)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_write(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex memory address to write (e.g. '0x7ff7a12b')."),
    value: str = Field(description="Value to write."),
    val_type: str = Field(description="Value type: 'byte', 'word', 'dword', 'qword', 'float', 'double', 'utf8', 'utf16', 'hex'.")
) -> Dict[str, Any]:
    """Write a value directly to a memory address."""
    try:
        success = memory.write_memory_address(session_id, address, value, val_type)
        return {"status": "success", "address": address, "written": success}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_write_all(
    session_id: str = Field(description="Active session ID."),
    value: str = Field(description="Value to write to all active candidates.")
) -> Dict[str, Any]:
    """Write the target value to all current search result candidate addresses simultaneously."""
    try:
        count = memory.write_all_candidates(session_id, value)
        return {"status": "success", "addresses_updated": count}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_freeze(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex address to lock (e.g. '0x7ff7a12b')."),
    value: str = Field(description="Value to write continuously (as a string)."),
    val_type: str = Field(description="Value type: 'byte', 'word', 'dword', 'qword', 'float', 'double'.")
) -> Dict[str, Any]:
    """Freeze/lock a memory value (rewritten every 100ms in a background interval thread)."""
    try:
        success = memory.freeze_memory_address(session_id, address, value, val_type)
        return {"status": "success", "address": address, "frozen": success}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_unfreeze(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex address to release from freezing.")
) -> Dict[str, Any]:
    """Stop locking/freezing memory at a specific address."""
    try:
        success = memory.unfreeze_memory_address(session_id, address)
        return {"status": "success", "address": address, "unfrozen": success}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_get_frozen(
    session_id: str = Field(description="Active session ID.")
) -> Dict[str, Any]:
    """Retrieve all locked/frozen addresses in this session."""
    try:
        frozen = memory.get_frozen_addresses(session_id)
        return {"status": "success", "frozen": frozen}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_patch_code(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex instruction address to patch (e.g., '0x7ff7a100')."),
    instruction: str = Field(description="Instruction patch: 'nop' or raw machine hexadecimal representation.")
) -> Dict[str, Any]:
    """Patch binary code/instructions in memory using Frida.patchCode()."""
    try:
        success = memory.patch_opcode_instruction(session_id, address, instruction)
        return {"status": "success", "patched": success}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_dump_range(
    session_id: str = Field(description="Active session ID."),
    start_address: str = Field(description="Hex starting address (e.g. '0x7ff7a100')."),
    size: int = Field(description="Number of bytes to dump.")
) -> Dict[str, Any]:
    """Dump a specific range of memory as raw bytes."""
    try:
        byte_list = memory.dump_memory_range(session_id, start_address, size)
        return {"status": "success", "size": len(byte_list), "bytes": byte_list}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# Host Saved List Database management tools
@mcp.tool()
def saved_list_load() -> Dict[str, Any]:
    """Load the global saved address list database."""
    try:
        items = memory.load_saved_list()
        return {"status": "success", "items": items}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def saved_list_add(
    name: str = Field(description="Friendly identifier name for this offset (e.g., 'Ammo')."),
    address: str = Field(description="Hex address (e.g., '0x7ff7a12c')."),
    val_type: str = Field(description="Value type definition."),
    comment: Optional[str] = Field(default="", description="Optional description.")
) -> Dict[str, Any]:
    """Save an offset/address to the local configuration for future sessions."""
    try:
        items = memory.save_to_list(name, address, val_type, comment or "")
        return {"status": "success", "items": items}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def saved_list_remove(
    address: str = Field(description="Hex address to delete from the saved config database.")
) -> Dict[str, Any]:
    """Delete a saved offset address from the local configuration database."""
    try:
        items = memory.remove_from_saved_list(address)
        return {"status": "success", "items": items}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# Script Run Tooling
@mcp.tool()
def execute_js_script(
    session_id: str = Field(description="Active session ID."),
    script_code: str = Field(description="JavaScript code utilizing the local 'gg' scripting interface object.")
) -> Dict[str, Any]:
    """Execute arbitrary JavaScript with Game Guardian `gg` API helpers directly in target process."""
    try:
        return memory.run_js_script(session_id, script_code)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def execute_lua_script(
    session_id: str = Field(description="Active session ID."),
    script_code: str = Field(description="Lua code utilizing the 'gg' global namespace.")
) -> Dict[str, Any]:
    """Execute a Game Guardian-style Lua script on the host, bridged to the target process."""
    try:
        return memory.run_lua_script(session_id, script_code)
    except Exception as e:
        return {"status": "error", "error": str(e)}


# Resources
@mcp.resource("frida://version")
def get_frida_version() -> str:
    """Retrieve the version of the installed Frida framework."""
    return frida.__version__


@mcp.resource("frida://devices")
def get_devices_as_string() -> str:
    """Get a list of all devices formatted as a string."""
    return "\n".join([
        f"ID: {d['id']} | Name: {d['name']} | Type: {d['type']}"
        for d in device.enumerate_devices()
    ])


@mcp.resource("frida://processes")
def get_processes_as_string() -> str:
    """Get a list of processes from the default USB device formatted as a string."""
    try:
        processes = device.list_running_processes()
        return "\n".join([f"PID: {p['pid']} | Name: {p['name']}" for p in processes])
    except Exception as e:
        return f"Error enumerating processes: {str(e)}"


@mcp.resource("frida://saved-list")
def get_saved_list_as_string() -> str:
    """Retrieve the global saved offsets list database as a readable string."""
    try:
        items = memory.load_saved_list()
        if not items:
            return "No offsets saved yet."
        return "\n".join([
            f"Name: {item['name']} | Address: {item['address']} | Type: {item['type']} | Comment: {item.get('comment', '')}"
            for item in items
        ])
    except Exception as e:
        return f"Error loading saved offsets: {str(e)}"


def main():
    """Command-line entry point."""
    mcp.run()


if __name__ == "__main__":
    main()
