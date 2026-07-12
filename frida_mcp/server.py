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
def list_applications(
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> List[Dict[str, Any]]:
    """List all installed applications on the selected device (useful for Android/iOS)."""
    return device.enumerate_applications(device_id)


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
    """Resume execution of a paused or suspended process using OS-level signal controls."""
    try:
        return device.resume_process_os(pid, device_id)
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def pause_process(
    pid: int = Field(description="Process ID to pause/suspend."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Pause/Suspend target process execution using OS-level STOP signal controls."""
    try:
        return device.suspend_process(pid, device_id)
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def process_status_details(
    pid: int = Field(description="Process ID to inspect."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Retrieve detailed state metrics, thread count, virtual size, RSS footprint, and parent PID details for a target process."""
    try:
        return device.get_process_status(pid, device_id)
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


@mcp.tool()
def dev_pull_file(
    remote_path: str = Field(description="Absolute path to the file on the remote device."),
    local_path: str = Field(description="Absolute path to save the file on the host machine.")
) -> Dict[str, Any]:
    """Pull/download a file from the target device to the host."""
    try:
        return device.pull_file(remote_path, local_path)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def dev_push_file(
    local_path: str = Field(description="Absolute path to the file on the host machine."),
    remote_path: str = Field(description="Absolute path to save the file on the remote device.")
) -> Dict[str, Any]:
    """Push/upload a file from the host machine to the target device."""
    try:
        return device.push_file(local_path, remote_path)
    except Exception as e:
        return {"status": "error", "error": str(e)}


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
def list_sessions() -> Dict[str, Any]:
    """List all active, open memory instrumentation sessions (like browser tabs)."""
    try:
        active = memory.get_active_sessions()
        return {"status": "success", "sessions": active}
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
def check_session_status(
    session_id: str = Field(description="Session ID to check health and status.")
) -> Dict[str, Any]:
    """Check the health status of an active session to verify if it is still connected or if the target process crashed."""
    try:
        return memory.check_session(session_id)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def reload_session_script(
    session_id: str = Field(description="Active session ID to reload.")
) -> Dict[str, Any]:
    """Hot-reload the instrumentation agent script without detaching from the target process."""
    try:
        return memory.reload_script(session_id)
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
def mem_allocate(
    session_id: str = Field(description="Active session ID."),
    size: int = Field(description="Size in bytes to allocate.")
) -> Dict[str, Any]:
    """Allocate memory in the target process."""
    try:
        addr = memory.allocate_memory(session_id, size)
        return {"status": "success", "address": addr}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_protect(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex memory address to protect."),
    size: int = Field(description="Size of region to protect."),
    protection: str = Field(description="Protection string (e.g. 'rw-', 'rwx').")
) -> Dict[str, Any]:
    """Change memory page protections."""
    try:
        success = memory.protect_memory(session_id, address, size, protection)
        return {"status": "success", "address": address, "protected": success}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_pointer_chain(
    session_id: str = Field(description="Active session ID."),
    base_address: str = Field(description="Base hex address."),
    offsets: List[str] = Field(description="List of hex or decimal offsets.")
) -> Dict[str, Any]:
    """Traverse a multi-level pointer chain."""
    try:
        return memory.traverse_pointer_chain(session_id, base_address, offsets)
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


@mcp.tool()
def mem_dump_hex(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex memory address or RVA offset (e.g. '0x4F23E58')."),
    size: int = Field(default=8, description="Number of bytes to dump."),
    library_name: Optional[str] = Field(default=None, description="If provided, 'address' is treated as an offset (RVA) from this library's base address (e.g. 'libil2cpp.so').")
) -> Dict[str, Any]:
    """Dump memory from a target address or library offset and return it as a formatted hex string."""
    try:
        # Resolve address if library_name is provided
        target_addr = address
        if library_name:
            resolved = memory.resolve_rva_address(session_id, address, library_name)
            if resolved.get("status") == "error":
                return resolved
            target_addr = resolved["absolute_address"]

        byte_list = memory.dump_memory_range(session_id, target_addr, size)
        
        # Format as hex string
        hex_str = " ".join([f"{b:02x}" for b in byte_list])
        
        return {
            "status": "success", 
            "address": target_addr,
            "size": len(byte_list), 
            "hex": hex_str
        }
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


# Quick Optimized Tools for Token Reduction
@mcp.tool()
def mem_quick_search_and_edit(
    pid: int = Field(description="Target Process ID (PID)."),
    search_val: str = Field(description="Value to search for."),
    val_type: str = Field(description="Value data type."),
    write_val: str = Field(description="New value to write to matching results."),
    device_id: Optional[str] = Field(default=None, description="Optional Device ID.")
) -> Dict[str, Any]:
    """Search and replace all matches in a target process in a single invocation to save AI tokens."""
    try:
        return memory.quick_search_and_edit(pid, search_val, val_type, write_val, device_id)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_quick_patch_offsets(
    session_id: str = Field(description="Active session ID."),
    patches: List[Dict[str, str]] = Field(description="List of patch objects, each containing 'address' and 'instruction' (e.g. 'nop' or hex string)."),
    library_name: str = Field(default="libil2cpp.so", description="Optional base library name to offset RVAs. Default is libil2cpp.so.")
) -> Dict[str, Any]:
    """Patch multiple code addresses (OPCODEs/hex) in a single call.
    Automatically resolves library base address and adds it to RVA offsets if they look like relative offsets.
    """
    try:
        pid = int(session_id.split("_")[1])
        base_addr = memory._get_lib_base_via_adb(pid, library_name)
        if not base_addr:
            return {"status": "error", "message": f"Could not resolve base address for {library_name}"}
        
        base_int = int(base_addr, 16)
        
        resolved_patches = []
        for p in patches:
            addr_str = p.get("address", "")
            offset = int(addr_str, 16)
            # If the offset is relatively small, it's an RVA. Add base.
            if offset < 0x10000000:
                abs_addr = hex(base_int + offset)
            else:
                abs_addr = hex(offset)
            resolved_patches.append({"address": abs_addr, "instruction": p.get("instruction")})
            
        return memory.quick_patch_addresses(session_id, resolved_patches)
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
def mem_quick_freeze_list(
    session_id: str = Field(description="Active session ID."),
    freeze_list: List[Dict[str, str]] = Field(description="List of items to freeze, each containing 'address', 'value', and optional 'type'.")
) -> Dict[str, Any]:
    """Freeze multiple memory addresses simultaneously in a single call to save AI tokens."""
    try:
        return memory.quick_freeze_addresses(session_id, freeze_list)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_enumerate_modules(
    session_id: str = Field(description="Active session ID.")
) -> Dict[str, Any]:
    """Enumerate all loaded modules/libraries in the process."""
    try:
        modules = memory.enumerate_modules(session_id)
        return {"status": "success", "modules": modules}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_get_exports(
    session_id: str = Field(description="Active session ID."),
    module_name: str = Field(description="Name of the module (e.g. 'libil2cpp.so').")
) -> Dict[str, Any]:
    """Retrieve exports from a specific module."""
    try:
        exports = memory.get_module_exports(session_id, module_name)
        return {"status": "success", "exports": exports}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_get_imports(
    session_id: str = Field(description="Active session ID."),
    module_name: str = Field(description="Name of the module.")
) -> Dict[str, Any]:
    """Retrieve imports for a specific module."""
    try:
        imports = memory.get_module_imports(session_id, module_name)
        return {"status": "success", "imports": imports}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_get_symbols(
    session_id: str = Field(description="Active session ID."),
    module_name: str = Field(description="Name of the module.")
) -> Dict[str, Any]:
    """Retrieve symbols for a specific module."""
    try:
        symbols = memory.get_module_symbols(session_id, module_name)
        return {"status": "success", "symbols": symbols}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_dump_dex(
    session_id: str = Field(description="Active session ID.")
) -> Dict[str, Any]:
    """Scan process memory for DEX file magic headers and dump their addresses and sizes."""
    try:
        return memory.dump_dex(session_id)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_va_to_rva(
    session_id: str = Field(description="Active session ID."),
    module_name: str = Field(description="Name of the module."),
    va: str = Field(description="Absolute Virtual Address (VA) in hex.")
) -> Dict[str, Any]:
    """Convert an absolute virtual address (VA) to a relative virtual address (RVA) for a given module."""
    try:
        return memory.va_to_rva(session_id, module_name, va)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_find_translated_library(
    session_id: str = Field(description="Active session ID."),
    library_name: str = Field(description="Name of the library/module (e.g. 'libil2cpp.so').")
) -> Dict[str, Any]:
    """Identify the virtual memory base address of translated ARM libraries in memory maps (such as Houdini translation environments)."""
    try:
        return memory.find_translated_library(session_id, library_name)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_dump_library(
    session_id: str = Field(description="Active session ID."),
    library_name: str = Field(description="Shared library module name (e.g. 'libil2cpp.so')."),
    output_path: str = Field(description="Workspace destination filepath on the host filesystem (e.g. 'c:\\Users\\mdrab\\Desktop\\libil2cpp.bin').")
) -> Dict[str, Any]:
    """Dynamically parses and dumps fully decrypted shared libraries from memory maps to host workspace."""
    try:
        return memory.dump_library_memory(session_id, library_name, output_path)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_dump_metadata_search(
    session_id: str = Field(description="Active session ID."),
    output_path: str = Field(description="Workspace destination metadata filepath on the host filesystem (e.g. 'c:\\Users\\mdrab\\Desktop\\global-metadata.dat').")
) -> Dict[str, Any]:
    """Runs a safe signature sweep for global-metadata magic bytes and dumps decrypted metadata to the host."""
    try:
        return memory.dump_metadata_by_signature(session_id, output_path)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_resolve_rva(
    session_id: str = Field(description="Active session ID."),
    rva: str = Field(description="Relative Virtual Address from dump file (e.g., '0x1D6E334' or '1D6E334')."),
    library_name: str = Field(default="libil2cpp.so", description="Library module name (defaults to 'libil2cpp.so').")
) -> Dict[str, Any]:
    """Resolves an RVA (Relative Virtual Address) offset from a dump file to a live absolute process memory address at runtime."""
    try:
        return memory.resolve_rva_address(session_id, rva, library_name)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_hook_function(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex memory address to hook (e.g. '0x994f1334')."),
    val_type: Optional[str] = Field(default=None, description="Optional return value override type ('boolean', 'int', 'qword')."),
    override_val: Optional[str] = Field(default=None, description="Optional value to override return value (e.g., 'true', '1').")
) -> Dict[str, Any]:
    """Dynamically hooks/intercepts target function calls using Frida Interceptor, recording arguments and optional return values."""
    try:
        return memory.hook_function(session_id, address, val_type, override_val)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_get_hook_logs(
    session_id: str = Field(description="Active session ID.")
) -> Dict[str, Any]:
    """Retrieve logged intercept events from any active function hooks in this session."""
    try:
        return memory.get_hook_logs(session_id)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_quick_hook_offsets(
    session_id: str = Field(description="Active session ID."),
    offsets: List[str] = Field(description="List of Relative Virtual Address offsets (hex strings, e.g. ['0x4F23E58', '0x50AB1F0']) to hook."),
    val_type: str = Field(default="boolean", description="Data type of the return value to override ('boolean', 'int', 'qword')."),
    override_val: str = Field(default="true", description="Value to override the return value with (e.g. 'true', '1', '0')."),
    library_name: str = Field(default="libil2cpp.so", description="Shared library name (defaults to 'libil2cpp.so').")
) -> Dict[str, Any]:
    """Stealthily hooks multiple function offsets simultaneously in a target module to override their return values, with automatic linker load handling."""
    try:
        return memory.quick_hook_offsets(session_id, offsets, val_type, override_val, library_name)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_unhook_function(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex memory address to unhook.")
) -> Dict[str, Any]:
    """Detach/remove a previously installed hook from a function."""
    try:
        success = memory.unhook_function(session_id, address)
        return {"status": "success", "address": address, "unhooked": success}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_trace_call_tree(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex memory address to start tracing."),
    depth: int = Field(default=3, description="Maximum call depth to trace.")
) -> Dict[str, Any]:
    """Attach a tracer to trace call depth (enter/leave events)."""
    try:
        return memory.trace_call_tree(session_id, address, depth)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_hook_exports(
    session_id: str = Field(description="Active session ID."),
    module_name: str = Field(description="Name of the module to hook exports in.")
) -> Dict[str, Any]:
    """Hook all exported functions in a module to log when they are called."""
    try:
        return memory.hook_module_exports(session_id, module_name)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_hook_imports(
    session_id: str = Field(description="Active session ID."),
    module_name: str = Field(description="Name of the module to hook imports in.")
) -> Dict[str, Any]:
    """Hook all imported functions in a module to log when they are called."""
    try:
        return memory.hook_module_imports(session_id, module_name)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_enumerate_threads(
    session_id: str = Field(description="Active session ID.")
) -> Dict[str, Any]:
    """Enumerate all active threads in the process, retrieving their IDs, execution state, and CPU register contexts."""
    try:
        threads = memory.enumerate_threads(session_id)
        return {"status": "success", "threads": threads}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_backtrace_thread(
    session_id: str = Field(description="Active session ID."),
    thread_id: int = Field(description="Thread ID to backtrace.")
) -> Dict[str, Any]:
    """Retrieve an accurate execution stack backtrace for a specific thread, resolving addresses to function symbols if available."""
    try:
        return memory.backtrace_thread(session_id, thread_id)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_call_native_function(
    session_id: str = Field(description="Active session ID."),
    address: str = Field(description="Hex memory address of the native function."),
    return_type: str = Field(description="Return type (e.g., 'void', 'pointer', 'int', 'float')."),
    arg_types: List[str] = Field(description="List of argument types (e.g., ['int', 'pointer'])."),
    args_list: List[Any] = Field(description="List of argument values matching arg_types.")
) -> Dict[str, Any]:
    """Dynamically call a native function at a specific memory address."""
    try:
        return memory.call_native_function(session_id, address, return_type, arg_types, args_list)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_create_native_function(
    session_id: str = Field(description="Active session ID."),
    func_id: str = Field(description="A unique string ID to identify this function later."),
    address: str = Field(description="Hex memory address of the native function."),
    return_type: str = Field(description="Return type (e.g., 'void', 'pointer', 'int', 'float')."),
    arg_types: List[str] = Field(description="List of argument types (e.g., ['int', 'pointer']).")
) -> Dict[str, Any]:
    """Cache a NativeFunction by an ID to be invoked multiple times without re-parsing signatures."""
    try:
        return memory.create_native_function(session_id, func_id, address, return_type, arg_types)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_invoke_native_function(
    session_id: str = Field(description="Active session ID."),
    func_id: str = Field(description="The unique string ID of the previously created NativeFunction."),
    args_list: List[Any] = Field(description="List of argument values.")
) -> Dict[str, Any]:
    """Invoke a previously registered NativeFunction using its ID."""
    try:
        return memory.invoke_native_function(session_id, func_id, args_list)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_create_native_callback(
    session_id: str = Field(description="Active session ID."),
    cb_id: str = Field(description="A unique string ID to identify this callback in the hook logs."),
    return_type: str = Field(description="Return type of the callback (e.g., 'void', 'pointer', 'int')."),
    arg_types: List[str] = Field(description="List of argument types.")
) -> Dict[str, Any]:
    """Create a NativeCallback at runtime that logs its arguments to hook logs when invoked by the target app. Returns the memory address pointer to the callback."""
    try:
        return memory.create_native_callback(session_id, cb_id, return_type, arg_types)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_hook_register_natives(
    session_id: str = Field(description="Active session ID.")
) -> Dict[str, Any]:
    """Hook Android's JNIEnv->RegisterNatives to dynamically dump native JNI methods (names, signatures, pointers) as they are registered."""
    try:
        return memory.hook_register_natives(session_id)
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool()
def mem_invoke_exported_function(
    session_id: str = Field(description="Active session ID."),
    module_name: str = Field(description="Name of the module containing the export."),
    export_name: str = Field(description="Name of the exported function to call."),
    return_type: str = Field(description="Return type (e.g., 'void', 'pointer', 'int')."),
    arg_types: List[str] = Field(description="List of argument types."),
    args_list: List[Any] = Field(description="List of argument values.")
) -> Dict[str, Any]:
    """Dynamically lookup and invoke an exported function from a loaded module."""
    try:
        return memory.invoke_exported_function(session_id, module_name, export_name, return_type, arg_types, args_list)
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
