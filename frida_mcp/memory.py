# Memory Search and Manipulation Controller

import pathlib
import json
import time
import frida
from typing import Dict, List, Optional, Any
from .device import get_target_device

# Optional Lupa binding for Game Guardian Lua scripts
try:
    import lupa
    LUA_AVAILABLE = True
except ImportError:
    LUA_AVAILABLE = False

_sessions: Dict[str, frida.core.Session] = {}
_scripts: Dict[str, frida.core.Script] = {}

# Saved lists config folder
SAVE_LIST_PATH = pathlib.Path.home() / ".frida_mcp_save_list.json"

AGENT_JS_PATH = pathlib.Path(__file__).parent / "agent" / "agent.js"

def get_agent_code() -> str:
    """Read the in-process JS agent code."""
    if not AGENT_JS_PATH.exists():
        raise FileNotFoundError(f"Frida agent file not found at {AGENT_JS_PATH}")
    return AGENT_JS_PATH.read_text(encoding="utf-8")

def create_memory_session(pid: int, device_id: Optional[str] = None) -> str:
    """Attach to target process, load high-performance JS agent, and return session_id."""
    device = get_target_device(device_id)
    session = device.attach(pid)
    
    session_id = f"session_{pid}_{int(time.time())}"
    agent_code = get_agent_code()
    
    script = session.create_script(agent_code)
    script.load()
    
    _sessions[session_id] = session
    _scripts[session_id] = script
    return session_id

def close_memory_session(session_id: str) -> None:
    """Safely detach and unload agent from session."""
    if session_id in _scripts:
        try:
            _scripts[session_id].unload()
        except Exception:
            pass
        del _scripts[session_id]
        
    if session_id in _sessions:
        try:
            _sessions[session_id].detach()
        except Exception:
            pass
        del _sessions[session_id]
def get_active_sessions() -> List[Dict[str, Any]]:
    """List all open memory sessions (browser tabs equivalent)."""
    return [
        {"session_id": sid, "pid": int(sid.split("_")[1]) if len(sid.split("_")) > 1 else 0}
        for sid in _sessions.keys()
    ]

def get_session_rpc(session_id: str):
    """Retrieve the RPC endpoints of the loaded agent."""
    if session_id not in _scripts:
        raise ValueError(f"Session '{session_id}' is not active or has been detached.")
    return _scripts[session_id].exports

# Memory Search & Manipulation RPC call mappings
def search_memory(session_id: str, value: str, val_type: str, regions: Optional[List[str]] = None, xor_key: Optional[int] = None) -> int:
    """Scan memory ranges for a value."""
    rpc = get_session_rpc(session_id)
    return rpc.search_value(value, val_type, regions or [], xor_key or 0)

def refine_memory(session_id: str, value: str, mode: str = "exact") -> int:
    """Refine search results (exact, increased, decreased, changed, unchanged)."""
    rpc = get_session_rpc(session_id)
    return rpc.refine_value(value, mode)

def search_pointers_resolving_to_candidates(session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Scan memory regions to find pointers pointing to active search candidates."""
    rpc = get_session_rpc(session_id)
    return rpc.search_pointers(limit)

def group_search_memory(session_id: str, group_str: str, max_distance: int = 100, regions: Optional[List[str]] = None) -> int:
    """Search for multiple values separated by semicolon (e.g. '100;50;99') close to each other."""
    rpc = get_session_rpc(session_id)
    return rpc.group_search(group_str, max_distance, regions or [])

def get_candidates_list(session_id: str, limit: int = 100) -> Dict[str, Any]:
    """Retrieve current search result candidates."""
    rpc = get_session_rpc(session_id)
    return rpc.get_candidates(limit)

def write_memory_address(session_id: str, address: str, value: str, val_type: str) -> bool:
    """Write value directly to specified memory location."""
    rpc = get_session_rpc(session_id)
    return rpc.write_value(address, value, val_type)

def write_all_candidates(session_id: str, value: str) -> int:
    """Batch edit values of all matching search result candidates."""
    rpc = get_session_rpc(session_id)
    return rpc.edit_all_candidates(value)

def freeze_memory_address(session_id: str, address: str, value: str, val_type: str) -> bool:
    """Freeze value at specified address (locks variable value)."""
    rpc = get_session_rpc(session_id)
    return rpc.freeze_value(address, value, val_type)

def unfreeze_memory_address(session_id: str, address: str) -> bool:
    """Stop freezing memory address."""
    rpc = get_session_rpc(session_id)
    return rpc.unfreeze_value(address)

def get_frozen_addresses(session_id: str) -> Dict[str, Any]:
    """List all frozen memory locations."""
    rpc = get_session_rpc(session_id)
    return rpc.get_frozen()

def patch_opcode_instruction(session_id: str, address: str, instruction: str) -> bool:
    """Patch machine code/opcodes at target memory address."""
    rpc = get_session_rpc(session_id)
    return rpc.patch_opcode(address, instruction)

def dump_memory_range(session_id: str, start_address: str, size: int) -> List[int]:
    """Dump a specific memory range back as a list of bytes."""
    rpc = get_session_rpc(session_id)
    return rpc.dump_memory_range(start_address, size)

# Host-Side Saved Lists Manager
def load_saved_list() -> List[Dict[str, Any]]:
    """Load the global saved address lists from local disk."""
    if not SAVE_LIST_PATH.exists():
        return []
    try:
        return json.loads(SAVE_LIST_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []

def save_to_list(name: str, address: str, val_type: str, comment: str = "") -> List[Dict[str, Any]]:
    """Save an address to local saved list database."""
    current = load_saved_list()
    # Check if address already exists in list, update it, otherwise append
    exists = False
    for item in current:
        if item.get("address").lower() == address.lower():
            item["name"] = name
            item["type"] = val_type
            item["comment"] = comment
            exists = True
            break
    if not exists:
        current.append({
            "name": name,
            "address": address,
            "type": val_type,
            "comment": comment
        })
    SAVE_LIST_PATH.write_text(json.dumps(current, indent=4), encoding="utf-8")
    return current

def remove_from_saved_list(address: str) -> List[Dict[str, Any]]:
    """Remove address from local saved list database."""
    current = load_saved_list()
    next_list = [item for item in current if item.get("address").lower() != address.lower()]
    SAVE_LIST_PATH.write_text(json.dumps(next_list, indent=4), encoding="utf-8")
    return next_list

# Script Runner engines
def run_js_script(session_id: str, js_code: str) -> Dict[str, Any]:
    """Runs JavaScript in target with `gg` helpers."""
    rpc = get_session_rpc(session_id)
    return rpc.execute_script_js(js_code)

class LuaGG:
    """Lua mapped Game Guardian commands executing via Frida RPC."""
    def __init__(self, rpc):
        self.rpc = rpc

    def searchNumber(self, val, val_type, regions=None, xor_key=0):
        # lupa automatically bridges Lua tables to python lists
        reg_list = list(regions) if regions else []
        return self.rpc.search_value(str(val), val_type, reg_list, int(xor_key))

    def refineNumber(self, val, mode="exact"):
        return self.rpc.refine_value(str(val), mode)

    def getResults(self, limit=100):
        res = self.rpc.get_candidates(limit)
        return res.get("results", [])

    def editAll(self, val, val_type=None):
        return self.rpc.edit_all_candidates(str(val))

    def setValues(self, list_of_items):
        for item in list_of_items:
            addr = item.get("address")
            val = item.get("value")
            t = item.get("type")
            self.rpc.write_value(addr, str(val), t)

    def freeze(self, addr, val, val_type=None):
        return self.rpc.freeze_value(addr, str(val), val_type)

    def unfreeze(self, addr):
        return self.rpc.unfreeze_value(addr)

def run_lua_script(session_id: str, lua_code: str) -> Dict[str, Any]:
    """Execute Game Guardian Lua script using host Python bridge."""
    if not LUA_AVAILABLE:
        return {
            "status": "error",
            "message": "Lua runtime is not installed on the host. Run 'pip install lupa' to enable Lua scripting."
        }
    
    rpc = get_session_rpc(session_id)
    try:
        lua = lupa.LuaRuntime(unpack_returned_tuples=True)
        gg = LuaGG(rpc)
        lua.globals().gg = gg
        
        result = lua.execute(lua_code)
        return {
            "status": "success",
            "result": str(result) if result is not None else "success"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Lua runtime exception: {str(e)}"
        }

def resolve_module(session_id: str, module_name: str) -> Dict[str, Any]:
    """Get the base address and size of a module relative to session."""
    rpc = get_session_rpc(session_id)
    return rpc.resolve_module(module_name)

def read_pointer_chain(session_id: str, base_address: str, offsets: List[int], val_type: str = "dword") -> Dict[str, Any]:
    """Read a value at the end of a pointer chain starting from a base address."""
    rpc = get_session_rpc(session_id)
    # Convert list of offsets to string equivalents for JS arrays
    offset_strs = [str(o) for o in offsets]
    return rpc.read_pointer_chain(base_address, offset_strs, val_type)

def patch_return(session_id: str, address: str, return_type: str, value: str) -> Dict[str, Any]:
    """Hook a function and force it to return a specific value (bool, int, dword)."""
    rpc = get_session_rpc(session_id)
    return rpc.patch_return(address, return_type, value)

