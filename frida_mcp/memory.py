# Memory Search and Manipulation Controller

import pathlib
import json
import time
import subprocess
import concurrent.futures
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
_session_status: Dict[str, str] = {}  # session_id -> "active" | "detached"

# Saved lists config folder
SAVE_LIST_PATH = pathlib.Path.home() / ".frida_mcp_save_list.json"

AGENT_JS_PATH = pathlib.Path(__file__).parent / "agent" / "agent.js"

RPC_TIMEOUT = 15  # seconds before an RPC call is considered hung

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def get_agent_code() -> str:
    """Read the in-process JS agent code."""
    if not AGENT_JS_PATH.exists():
        raise FileNotFoundError(f"Frida agent file not found at {AGENT_JS_PATH}")
    return AGENT_JS_PATH.read_text(encoding="utf-8")


def _rpc_call(rpc, method: str, *args, timeout: int = RPC_TIMEOUT):
    """Call an RPC method with a timeout. Raises TimeoutError if it hangs."""
    fn = getattr(rpc, method)
    future = _executor.submit(fn, *args)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise TimeoutError(f"RPC '{method}' timed out after {timeout}s — Frida may be hung or disconnected")


def _auto_cleanup(session_id: str, reason):
    """Called automatically when Frida detaches — cleans up session state."""
    _session_status[session_id] = f"detached: {reason}"
    _scripts.pop(session_id, None)
    _sessions.pop(session_id, None)


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
    _session_status[session_id] = "active"

    # Auto-cleanup on disconnect
    session.on("detached", lambda reason: _auto_cleanup(session_id, reason))

    return session_id


def check_session(session_id: str) -> Dict[str, Any]:
    """Returns health status of a session — alive, detached, or unknown."""
    status = _session_status.get(session_id)
    if session_id in _scripts and session_id in _sessions:
        return {"session_id": session_id, "status": "active"}
    elif status:
        return {"session_id": session_id, "status": status}
    return {"session_id": session_id, "status": "not_found"}


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

    _session_status.pop(session_id, None)


def get_active_sessions() -> List[Dict[str, Any]]:
    """List all open memory sessions (browser tabs equivalent)."""
    return [
        {"session_id": sid, "pid": int(sid.split("_")[1]) if len(sid.split("_")) > 1 else 0}
        for sid in _sessions.keys()
    ]


class _RpcProxy:
    """Wraps Frida script.exports — adds session-alive check + timeout to every RPC call."""
    __slots__ = ("_sid", "_exports")

    def __init__(self, session_id: str, exports):
        object.__setattr__(self, "_sid", session_id)
        object.__setattr__(self, "_exports", exports)

    def __getattr__(self, name):
        sid = object.__getattribute__(self, "_sid")
        exports = object.__getattribute__(self, "_exports")

        def _call(*args):
            # Check session still alive before every call
            if sid not in _scripts:
                status = _session_status.get(sid, "detached")
                raise ConnectionError(
                    f"Session '{sid}' is no longer active ({status}). "
                    "Process may have crashed. Re-open the session."
                )
            fn = getattr(exports, name)
            future = _executor.submit(fn, *args)
            try:
                return future.result(timeout=RPC_TIMEOUT)
            except concurrent.futures.TimeoutError:
                raise TimeoutError(
                    f"RPC '{name}' timed out after {RPC_TIMEOUT}s. "
                    "Process may be frozen or crashed."
                )
        return _call


def get_session_rpc(session_id: str) -> "_RpcProxy":
    """Retrieve the RPC proxy for the loaded agent (with crash detection + timeout)."""
    if session_id not in _scripts:
        status = _session_status.get(session_id, "not_found")
        raise ValueError(f"Session '{session_id}' is not active ({status}). Re-open the session.")
    return _RpcProxy(session_id, _scripts[session_id].exports)


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

def allocate_memory(session_id: str, size: int) -> str:
    """Allocate memory in the target process."""
    rpc = get_session_rpc(session_id)
    return rpc.allocate_memory(size)

def protect_memory(session_id: str, address: str, size: int, protection: str) -> bool:
    """Change memory protection (e.g. 'rw-', 'rwx')."""
    rpc = get_session_rpc(session_id)
    return rpc.protect_memory(address, size, protection)

def traverse_pointer_chain(session_id: str, base_addr: str, offsets: List[str]) -> Dict[str, Any]:
    """Traverse a multi-level pointer chain."""
    rpc = get_session_rpc(session_id)
    return rpc.traverse_pointer_chain(base_addr, offsets)

def enumerate_modules(session_id: str) -> List[Dict[str, Any]]:
    """Enumerate all loaded modules/libraries in the process."""
    rpc = get_session_rpc(session_id)
    return rpc.enumerate_modules()

def get_module_exports(session_id: str, module_name: str) -> List[Dict[str, Any]]:
    """Retrieve exports from a specific module."""
    rpc = get_session_rpc(session_id)
    return rpc.get_module_exports(module_name)

def get_module_imports(session_id: str, module_name: str) -> List[Dict[str, Any]]:
    """Retrieve imports for a specific module."""
    rpc = get_session_rpc(session_id)
    return rpc.get_module_imports(module_name)

def get_module_symbols(session_id: str, module_name: str) -> List[Dict[str, Any]]:
    """Retrieve symbols for a specific module."""
    rpc = get_session_rpc(session_id)
    return rpc.get_module_symbols(module_name)

def va_to_rva(session_id: str, module_name: str, va: str) -> Dict[str, Any]:
    """Convert an absolute virtual address (VA) to a relative virtual address (RVA) for a given module."""
    rpc = get_session_rpc(session_id)
    return rpc.va_to_rva(module_name, va)

def get_frozen_addresses(session_id: str) -> Dict[str, Any]:
    """List all frozen memory locations."""
    rpc = get_session_rpc(session_id)
    return rpc.get_frozen()

def unhook_function(session_id: str, address: str) -> bool:
    """Detach a hook from a function."""
    rpc = get_session_rpc(session_id)
    return rpc.unhook_function(address)

def trace_call_tree(session_id: str, address: str, depth: int) -> Dict[str, Any]:
    """Attach an Interceptor to trace call tree enter/leave depth."""
    rpc = get_session_rpc(session_id)
    return rpc.trace_call_tree(address, depth)

def hook_module_exports(session_id: str, module_name: str) -> Dict[str, Any]:
    """Hook all exports in a module to log when they are called."""
    rpc = get_session_rpc(session_id)
    return rpc.hook_module_exports(module_name)

def hook_module_imports(session_id: str, module_name: str) -> Dict[str, Any]:
    """Hook all imports in a module to log when they are called."""
    rpc = get_session_rpc(session_id)
    return rpc.hook_module_imports(module_name)

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

def from_lua(val):
    if val is None:
        return None
    if hasattr(val, 'items'):
        length = len(val)
        if length > 0:
            keys = set(val.keys())
            if keys == set(range(1, length + 1)):
                return [from_lua(val[i]) for i in range(1, length + 1)]
        return {k: from_lua(v) for k, v in val.items()}
    return val

class LuaGG:
    """Lua mapped Game Guardian commands executing via Frida RPC."""
    TYPE_DWORD = 4
    REGION_C_ALLOC = 1
    REGION_ANONYMOUS = 2
    REGION_OTHER = 4
    REGION_JAVA_HEAP = 8
    REGION_C_DATA = 16
    REGION_C_BSS = 32

    def __init__(self, rpc, lua_runtime):
        self.rpc = rpc
        self.lua = lua_runtime
        self.search_regions = []

    def __getattr__(self, name):
        # Allow case-insensitive/lowercase resolution for Lupa GG compatibility
        lower_name = name.lower()
        for attr in dir(self):
            if attr.lower() == lower_name:
                return getattr(self, attr)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def to_lua_table(self, data):
        """Helper to convert nested python data structures to native Lupa Lua tables."""
        if isinstance(data, list) or isinstance(data, tuple):
            t = self.lua.table()
            for idx, val in enumerate(data, start=1):
                t[idx] = self.to_lua_table(val)
            return t
        elif isinstance(data, dict):
            t = self.lua.table()
            for k, val in data.items():
                t[k] = self.to_lua_table(val)
            return t
        return data

    def alert(self, msg):
        safe_msg = str(msg).encode('ascii', errors='replace').decode('ascii')
        print(f"[GG Alert] {safe_msg}")
        return True

    def toast(self, msg):
        safe_msg = str(msg).encode('ascii', errors='replace').decode('ascii')
        print(f"[GG Toast] {safe_msg}")
        return True

    def choice(self, options=None, default=1, title=""):
        opts = from_lua(options) or []
        safe_title = str(title).encode('ascii', errors='replace').decode('ascii')
        safe_opts = [str(o).encode('ascii', errors='replace').decode('ascii') for o in opts]
        print(f"[GG Choice] {safe_title} - Options: {safe_opts} (Recommended: {default})")
        import os
        override = os.environ.get("GG_CHOICE_OVERRIDE")
        if override:
            try:
                return int(override)
            except ValueError:
                pass
        
        # Track menu interaction state
        if not hasattr(self, '_choice_count'):
            self._choice_count = 0
        self._choice_count += 1

        # First Choice: Main Menu (Option 1: Dump Libil2cpp.so)
        if len(opts) > 0 and "Dump Libil2cpp.so" in str(opts[0]):
            if self._choice_count > 1:
                # Unattended run: Exit on subsequent main menu returns
                print("[GG Choice] Exiting main menu to prevent infinite loop.")
                return None
            return 1
        
        # Second Choice: Library Selection Menu (Options list containing names)
        # Select the recommended/largest index automatically
        return int(default) if default else 1

    def prompt(self, prompts=None, defaults=None, types=None):
        prompts_list = from_lua(prompts) or []
        defaults_list = from_lua(defaults) or []
        types_list = from_lua(types) or []
        safe_prompts = [str(p).encode('ascii', errors='replace').decode('ascii') for p in prompts_list]
        safe_defaults = [str(d).encode('ascii', errors='replace').decode('ascii') for d in defaults_list]
        print(f"[GG Prompt] {safe_prompts} (Defaults: {safe_defaults})")
        
        res = []
        for i in range(len(prompts_list)):
            val = None
            t = types_list[i] if i < len(types_list) else 'text'
            if t == 'checkbox':
                val = False
            elif i < len(defaults_list):
                val = defaults_list[i]
            
            if val is None:
                if t == 'number':
                    val = "2"
                else:
                    val = ""
            res.append(val)
        return self.to_lua_table(res)

    def getTargetInfo(self):
        info = self.rpc.get_target_info()
        pkg = info.get("packageName", "")
        label = info.get("label", "")
        if "app_process" in pkg or pkg == "unknown" or not pkg:
            pkg = "com.dts.freefireth"
            label = "Free Fire"
        return self.to_lua_table({
            "packageName": pkg,
            "label": label,
            "x64": info.get("x64", False)
        })

    def getRangesList(self, pattern=None):
        ranges = self.rpc.get_ranges_list(pattern)
        converted = []
        for r in ranges:
            try:
                converted.append({
                    "start": int(r["start"], 16),
                    "end": int(r["end"], 16),
                    "internalName": r["internalName"]
                })
            except Exception:
                pass
        return self.to_lua_table(converted)

    def clearResults(self):
        return self.rpc.clear_search()

    def setRanges(self, mask):
        regions = []
        mask = int(mask)
        if mask & self.REGION_ANONYMOUS:
            regions.append("anon")
        if mask & (self.REGION_C_ALLOC | self.REGION_C_DATA | self.REGION_C_BSS):
            regions.append("code")
        if mask & self.REGION_JAVA_HEAP:
            regions.append("heap")
        if mask & self.REGION_OTHER:
            regions.append("anon")
            
        self.search_regions = regions
        return True

    def searchNumber(self, val, val_type, regions=None, xor_key=0):
        val_str = str(val)
        if val_str.endswith("h"):
            val_str = str(int(val_str[:-1], 16))
            
        t_str = "dword"
        val_type = int(val_type)
        if val_type == 1: t_str = "byte"
        elif val_type == 2: t_str = "word"
        elif val_type == 4: t_str = "dword"
        elif val_type == 64: t_str = "qword"
        elif val_type == 16: t_str = "float"
        elif val_type == 32: t_str = "double"
        
        regs = self.search_regions if regions is None else from_lua(regions)
        return self.rpc.search_value(val_str, t_str, regs, int(xor_key))

    def refineNumber(self, val, mode="exact"):
        return self.rpc.refine_value(str(val), mode)

    def getResultsCount(self):
        res = self.rpc.get_candidates(1)
        return res.get("total", 0)

    def _parse_val(self, val):
        if val is None:
            return 0
        val_str = str(val)
        try:
            if "." in val_str or "e" in val_str.lower():
                return float(val_str)
            return int(val_str)
        except ValueError:
            return val_str

    def getResults(self, limit=100):
        res = self.rpc.get_candidates(limit)
        results = res.get("results", [])
        converted = []
        for item in results:
            converted.append({
                "address": int(item["address"], 16),
                "value": self._parse_val(item["value"]),
                "type": item["type"]
            })
        return self.to_lua_table(converted)

    def getValues(self, list_of_items):
        list_of_items = from_lua(list_of_items) or []
        rpc_items = []
        for item in list_of_items:
            rpc_items.append({
                "address": hex(int(item["address"])),
                "flags": int(item["flags"])
            })
        
        res = self.rpc.get_values_list(rpc_items)
        converted = []
        for item in res:
            converted.append({
                "address": int(item["address"], 16),
                "value": self._parse_val(item["value"]),
                "flags": item["flags"]
            })
        return self.to_lua_table(converted)

    def editAll(self, val, val_type=None):
        return self.rpc.edit_all_candidates(str(val))

    def setValues(self, list_of_items):
        list_of_items = from_lua(list_of_items) or []
        for item in list_of_items:
            addr = hex(int(item.get("address")))
            val = item.get("value")
            t = item.get("type", "dword")
            self.rpc.write_value(addr, str(val), t)

    def freeze(self, addr, val, val_type=None):
        return self.rpc.freeze_value(hex(int(addr)), str(val), val_type)

    def unfreeze(self, addr):
        return self.rpc.unfreeze_value(hex(int(addr)))

    def dumpMemory(self, starting, ending, path):
        size = int(ending) - int(starting) + 1
        print(f"[GG DumpMemory] Range: 0x{int(starting):x} - 0x{int(ending):x} (Size: {size} bytes) to {path}")
        
        dest_dir = pathlib.Path(sanitize_path(path))
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        pkg = self.getTargetInfo()["packageName"]
        sh = f"{int(starting):x}"
        eh = f"{int(ending):x}"
        file_name = f"{pkg}-{sh}-{eh}.bin"
        output_file = dest_dir / file_name
        
        chunk_size = 4 * 1024 * 1024
        bytes_written = 0
        
        with open(output_file, "wb") as f:
            for offset in range(0, size, chunk_size):
                curr_size = min(chunk_size, size - offset)
                curr_addr = hex(int(starting) + offset)
                print(f"[GG DumpMemory] Progress: {bytes_written / (1024*1024):.2f}MB / {size / (1024*1024):.2f}MB...", end="\r")
                chunk = self.rpc.dump_memory_range(curr_addr, curr_size)
                f.write(bytes(chunk))
                bytes_written += len(chunk)
                
        print(f"\n[GG DumpMemory] Successfully dumped memory to host: {output_file}")
        return True

def sanitize_path(p: str) -> str:
    p_str = str(p).replace("\\", "/")
    # Normalize prefix to host workspace dump folder
    for prefix in ["/sdcard/dump", "/storage/emulated/0/dump", "/sdcard", "/storage/emulated/0"]:
        if p_str.startswith(prefix):
            suffix = p_str[len(prefix):].lstrip("/")
            return f"c:/Users/mdrab/Desktop/Frida mcp/exclude/Dump/{suffix}"
    return p_str

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
        gg = LuaGG(rpc, lua)
        lua.globals().gg = gg
        
        # Intercept os.rename to map device paths onto Windows filesystem with Lua conventions
        def safe_rename(old, new):
            try:
                old_path = sanitize_path(old)
                new_path = sanitize_path(new)
                import os as pos
                if pos.path.exists(new_path):
                    try:
                        pos.remove(new_path)
                    except Exception:
                        pass
                pos.rename(old_path, new_path)
                return True
            except Exception as e:
                print(f"[GG safe_rename Error] {e}")
                return False
        lua.globals().os.rename = safe_rename
        
        result = lua.execute(lua_code)
        return {
            "status": "success",
            "result": str(result) if result is not None else "success"
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": f"Lua runtime exception: {str(e)}"
        }



def quick_search_and_edit(pid: int, search_val: str, val_type: str, write_val: str, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Search for a value and replace all occurrences in a single quick operation to reduce AI tokens."""
    session_id = create_memory_session(pid, device_id)
    try:
        matches = search_memory(session_id, search_val, val_type)
        if matches > 0:
            updated = write_all_candidates(session_id, write_val)
            return {"status": "success", "matches_found": matches, "updated_count": updated}
        return {"status": "success", "matches_found": 0, "updated_count": 0}
    finally:
        close_memory_session(session_id)

def quick_patch_addresses(session_id: str, patches: List[Dict[str, str]]) -> Dict[str, Any]:
    """Patch multiple code addresses (OPCODEs/hex) in a single call to save AI tokens."""
    rpc = get_session_rpc(session_id)
    results = {}
    for patch in patches:
        addr = patch.get("address")
        inst = patch.get("instruction")
        if addr and inst:
            try:
                success = rpc.patch_opcode(addr, inst)
                results[addr] = "patched" if success else "failed"
            except Exception as e:
                results[addr] = f"error: {str(e)}"
    return {"status": "success", "results": results}

def quick_freeze_addresses(session_id: str, freeze_list: List[Dict[str, str]]) -> Dict[str, Any]:
    """Freeze multiple memory addresses simultaneously in a single call to save AI tokens."""
    rpc = get_session_rpc(session_id)
    results = {}
    for item in freeze_list:
        addr = item.get("address")
        val = item.get("value")
        t = item.get("type", "dword")
        if addr and val:
            try:
                success = rpc.freeze_value(addr, str(val), t)
                results[addr] = "frozen" if success else "failed"
            except Exception as e:
                results[addr] = f"error: {str(e)}"
    return {"status": "success", "results": results}

def hook_function(session_id: str, address: str, val_type: Optional[str] = None, override_val: Optional[str] = None) -> Dict[str, Any]:
    """Intercepts function at target address, logs parameters, and optionally replaces return values."""
    rpc = get_session_rpc(session_id)
    success = rpc.register_hook(address, val_type or "", override_val or "")
    return {"status": "success", "address": address, "hooked": success}

def get_hook_logs(session_id: str) -> Dict[str, Any]:
    """Retrieve logged intercept events from the active hooking engine."""
    rpc = get_session_rpc(session_id)
    logs = rpc.get_hook_logs()
    return {"status": "success", "logs": logs}

def _get_lib_base_via_adb(pid: int, library_name: str) -> Optional[str]:
    """Fast host-side base address lookup via ADB grep on /proc/<pid>/maps. Non-blocking."""
    adb_paths = [
        "C:\\Program Files\\BlueStacks_nxt\\HD-Adb.exe",
        "adb"
    ]
    for adb in adb_paths:
        try:
            result = subprocess.run(
                [adb, "shell", "su", "-c", f"grep -m1 {library_name} /proc/{pid}/maps"],
                capture_output=True, text=True, timeout=3
            )
            line = result.stdout.strip()
            if line:
                return "0x" + line.split("-")[0]
        except Exception:
            pass
    return None


def quick_hook_offsets(
    session_id: str,
    offsets: List[str],
    val_type: str = "boolean",
    override_val: str = "true",
    library_name: str = "libil2cpp.so"
) -> Dict[str, Any]:
    """Stealthily hooks multiple function offsets, resolving base address on host (non-blocking)."""
    rpc = get_session_rpc(session_id)
    pid = int(session_id.split("_")[1])
    base_addr = _get_lib_base_via_adb(pid, library_name)
    result = rpc.quickHookOffsets(offsets, val_type, override_val, base_addr or "")
    return {"status": "success", "result": result, "base": base_addr}

def find_translated_library(session_id: str, library_name: str) -> Dict[str, Any]:
    """Scans for Houdini/translated ARM library base address in anonymous maps."""
    rpc = get_session_rpc(session_id)
    # Re-route request to scan anonymous memory regions on process
    try:
        # Search the biggest r-x anonymous segments
        js_code = """
        (function() {
            var maps = Process.enumerateRanges({protection: 'r-x', coalesce: true});
            var candidates = maps.filter(function(m) { return !m.file && m.size > 20*1024*1024; });
            if (candidates.length > 0) {
                return candidates[0].base.toString() + "," + candidates[0].size.toString();
            }
            return "not_found";
        })()
        """
        res = rpc.execute_script_js(js_code)
        if res.get("status") == "success" and res.get("result") != "not_found":
            parts = res.get("result").split(",")
            return {"status": "success", "base_address": parts[0], "size": int(parts[1]), "type": "translated_arm"}
        return {"status": "error", "message": "Could not locate translated ARM module base address."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def parse_elf_end(rpc, base_addr: int, is_64: bool) -> Optional[int]:
    """Parse ELF program headers dynamically from process memory to calculate size (including .bss)."""
    try:
        # Read Magic: verify is 0x464C457F (ELF)
        # 1 DWORD flag = 4
        magic_res = rpc.get_values_list([{"address": hex(base_addr), "flags": 4}])
        if not magic_res or int(magic_res[0]["value"]) != 0x464C457F:
            return None

        max_vend = 0
        if is_64:
            # Read Program Header Offset (e_phoff) at base + 32 (8 bytes, but small offset fits in dword)
            phoff_res = rpc.get_values_list([{"address": hex(base_addr + 32), "flags": 4}])
            # Offset 52: e_ehsize(2) | e_phentsize(2)
            dw52_res = rpc.get_values_list([{"address": hex(base_addr + 52), "flags": 4}])
            # Offset 56: e_phnum(2) | e_shentsize(2)
            dw56_res = rpc.get_values_list([{"address": hex(base_addr + 56), "flags": 4}])
            if not phoff_res or not dw52_res or not dw56_res:
                return None

            e_phoff = int(phoff_res[0]["value"])
            if e_phoff < 0:
                e_phoff += 0x100000000
            e_phentsize = int(dw52_res[0]["value"]) // 65536
            e_phnum = int(dw56_res[0]["value"]) % 65536
            if e_phentsize == 0 or e_phnum == 0:
                return None

            for i in range(e_phnum):
                ph_addr = base_addr + e_phoff + (i * e_phentsize)
                ptype_res = rpc.get_values_list([{"address": hex(ph_addr), "flags": 4}])
                if ptype_res and int(ptype_res[0]["value"]) == 1:  # PT_LOAD
                    vaddr_res = rpc.get_values_list([{"address": hex(ph_addr + 16), "flags": 4}])
                    memsz_res = rpc.get_values_list([{"address": hex(ph_addr + 40), "flags": 4}])
                    if vaddr_res and memsz_res:
                        p_vaddr = int(vaddr_res[0]["value"])
                        if p_vaddr < 0:
                            p_vaddr += 0x100000000
                        p_memsz = int(memsz_res[0]["value"])
                        if p_memsz < 0:
                            p_memsz += 0x100000000
                        vend = p_vaddr + p_memsz
                        if vend > max_vend:
                            max_vend = vend
        else:
            # ELF32: e_phoff at 28
            phoff_res = rpc.get_values_list([{"address": hex(base_addr + 28), "flags": 4}])
            # Offset 40: e_ehsize(2) | e_phentsize(2)
            dw40_res = rpc.get_values_list([{"address": hex(base_addr + 40), "flags": 4}])
            # Offset 44: e_phnum(2) | e_shentsize(2)
            dw44_res = rpc.get_values_list([{"address": hex(base_addr + 44), "flags": 4}])
            if not phoff_res or not dw40_res or not dw44_res:
                return None

            e_phoff = int(phoff_res[0]["value"])
            if e_phoff < 0:
                e_phoff += 0x100000000
            e_phentsize = int(dw40_res[0]["value"]) // 65536
            e_phnum = int(dw44_res[0]["value"]) % 65536
            if e_phentsize == 0 or e_phnum == 0:
                return None

            for i in range(e_phnum):
                ph_addr = base_addr + e_phoff + (i * e_phentsize)
                ptype_res = rpc.get_values_list([{"address": hex(ph_addr), "flags": 4}])
                if ptype_res and int(ptype_res[0]["value"]) == 1:  # PT_LOAD
                    vaddr_res = rpc.get_values_list([{"address": hex(ph_addr + 8), "flags": 4}])
                    memsz_res = rpc.get_values_list([{"address": hex(ph_addr + 20), "flags": 4}])
                    if vaddr_res and memsz_res:
                        p_vaddr = int(vaddr_res[0]["value"])
                        if p_vaddr < 0:
                            p_vaddr += 0x100000000
                        p_memsz = int(memsz_res[0]["value"])
                        if p_memsz < 0:
                            p_memsz += 0x100000000
                        vend = p_vaddr + p_memsz
                        if vend > max_vend:
                            max_vend = vend

        if max_vend > 0:
            if max_vend % 4096 != 0:
                max_vend = max_vend + (4096 - max_vend % 4096)
            return base_addr + max_vend
    except Exception as e:
        print(f"[ELF Parser Error] {e}")
    return None

def resolve_library_range(session_id: str, library_name: str) -> Dict[str, Any]:
    """Finds module ranges, groups by proximity, detects arch, and resolves start/end bytes."""
    rpc = get_session_rpc(session_id)
    
    # 1. Stealthy fast-path lookup using Process.findModuleByName
    try:
        mod_info = rpc.getModuleInfo(library_name)
        if mod_info:
            base_addr = int(mod_info["base"], 16)
            size = int(mod_info["size"])
            info = rpc.get_target_info()
            is_64 = info.get("x64", False)
            arch_name = "arm64-v8a" if is_64 else "armeabi-v7a"
            return {
                "status": "success",
                "start": hex(base_addr),
                "end": hex(base_addr + size - 1),
                "size": size,
                "arch": arch_name,
                "is_64": is_64,
                "method": "stealthy_findModule"
            }
    except Exception as e:
        print(f"[Stealth Module Resolution Error] {e}")

    # 2. Fallback to range enumeration
    ranges = rpc.get_ranges_list(library_name)
    if not ranges:
        return {"status": "error", "message": f"Could not find module mapping for: {library_name}"}

    # Sort ranges by start address
    ranges.sort(key=lambda r: int(r["start"], 16))

    # 2. Group ranges by proximity (gap > 100MB indicates separate dual mapping)
    groups = [[ranges[0]]]
    for i in range(1, len(ranges)):
        last_group = groups[-1]
        last_end = int(last_group[-1]["end"], 16)
        curr_start = int(ranges[i]["start"], 16)
        if (curr_start - last_end) > (100 * 1024 * 1024):
            groups.append([ranges[i]])
        else:
            last_group.append(ranges[i])

    # Choose group with the most segments (decrypted runtime layout)
    best_group = max(groups, key=len)
    base_addr = int(best_group[0]["start"], 16)
    named_end = int(best_group[-1]["end"], 16)

    # 3. Detect architecture
    info = rpc.get_target_info()
    is_64 = info.get("x64", False)
    
    # Analyze headers via test Ranges
    test_ranges = rpc.get_ranges_list("*.so")
    arch_name = "arm64-v8a" if is_64 else "armeabi-v7a"
    for r in test_ranges:
        name = r.get("internalName", "")
        if "arm64" in name or "aarch64" in name:
            is_64 = True
            arch_name = "arm64-v8a"
            break
        elif "x86_64" in name:
            is_64 = True
            arch_name = "x86_64"
            break
        elif "x86" in name:
            is_64 = False
            arch_name = "x86"
            break

    # Parse program headers
    elf_end = parse_elf_end(rpc, base_addr, is_64)
    if elf_end and elf_end > base_addr:
        return {
            "status": "success",
            "start": hex(base_addr),
            "end": hex(elf_end - 1),
            "size": elf_end - base_addr,
            "arch": arch_name,
            "is_64": is_64,
            "method": "elf_header"
        }

    return {
        "status": "success",
        "start": hex(base_addr),
        "end": hex(named_end - 1),
        "size": named_end - base_addr,
        "arch": arch_name,
        "is_64": is_64,
        "method": "named_range"
    }

def dump_library_memory(session_id: str, library_name: str, output_path: str) -> Dict[str, Any]:
    """Dynamically locates library boundary endpoints and dumps decrypted contents directly to host."""
    res = resolve_library_range(session_id, library_name)
    if res.get("status") == "error":
        return res

    start_addr = int(res["start"], 16)
    end_addr = int(res["end"], 16)
    size = res["size"]

    print(f"[Quick Library Dump] Range: {hex(start_addr)} - {hex(end_addr)} (Size: {size / (1024*1024):.2f}MB, Arch: {res['arch']}) to {output_path}")

    dest_file = pathlib.Path(output_path)
    dest_file.parent.mkdir(parents=True, exist_ok=True)

    rpc = get_session_rpc(session_id)
    chunk_size = 4 * 1024 * 1024
    bytes_written = 0

    try:
        with open(dest_file, "wb") as f:
            for offset in range(0, size, chunk_size):
                curr_size = min(chunk_size, size - offset)
                curr_addr = hex(start_addr + offset)
                chunk = rpc.dump_memory_range(curr_addr, curr_size)
                f.write(bytes(chunk))
                bytes_written += len(chunk)
        return {
            "status": "success",
            "message": f"Successfully dumped {library_name} memory directly to host.",
            "start_address": hex(start_addr),
            "end_address": hex(end_addr),
            "bytes_written": bytes_written,
            "arch": res["arch"]
        }
    except Exception as e:
        return {"status": "error", "message": f"Failed to dump library memory: {str(e)}"}

def resolve_rva_address(session_id: str, rva: str, library_name: str = "libil2cpp.so") -> Dict[str, Any]:
    """Resolves an RVA (Relative Virtual Address) to its live absolute process memory address at runtime."""
    res = resolve_library_range(session_id, library_name)
    if res.get("status") == "error":
        return res

    base_addr = int(res["start"], 16)
    
    # Parse RVA format
    rva_clean = str(rva).strip().lower()
    if rva_clean.startswith("0x"):
        offset = int(rva_clean, 16)
    else:
        try:
            offset = int(rva_clean, 16)
        except ValueError:
            offset = int(rva_clean, 10)

    target_addr = base_addr + offset
    return {
        "status": "success",
        "rva": hex(offset),
        "library_name": library_name,
        "library_base": hex(base_addr),
        "absolute_address": hex(target_addr)
    }

def dump_metadata_by_signature(session_id: str, output_path: str) -> Dict[str, Any]:
    """Sweeps memory safely for global-metadata magic bytes, verifies offset structure, and dumps metadata."""
    rpc = get_session_rpc(session_id)
    # Search for magic bytes signature little-endian (FAB11BAF) using exact signature sweep
    # Target only files mapping to global-metadata.dat or .dat directly to prevent JIT segfaults
    all_ranges = rpc.get_ranges_list("*.dat")
    if not all_ranges:
        # Fallback to searching all anonymous segments
        all_ranges = rpc.get_ranges_list()

    meta_addr = None
    for r in all_ranges:
        start_hex = r["start"]
        size = int(r["end"], 16) - int(start_hex, 16)
        if size <= 0:
            continue
        try:
            # Enumerate pages and scan signature
            # We search for signature FAB11BAF in the specified segment base
            # 1 DWORD = 4 bytes. FAB11BAF hex represents 4,205,943,727 decimal
            # We will use searchValue targeting this range specifically
            js_scan = f"""
            (function() {{
                try {{
                    var base = ptr("{start_hex}");
                    var size = {size};
                    // Test read to prevent crash
                    base.readU8();
                    var matches = Memory.scanSync(base, size, "af 1b b1 fa");
                    if (matches.length > 0) {{
                        return matches[0].address.toString();
                    }}
                }} catch(e) {{}}
                return "not_found";
            }})()
            """
            scan_res = rpc.execute_script_js(js_scan)
            if scan_res.get("status") == "success" and scan_res.get("result") != "not_found":
                found_addr = int(scan_res.get("result"), 16)
                # Verify version field at offset +4 is >= 15 and <= 40
                ver_res = rpc.get_values_list([{"address": hex(found_addr + 4), "flags": 4}])
                if ver_res:
                    ver = int(ver_res[0]["value"])
                    if 15 <= ver <= 40:
                        meta_addr = found_addr
                        break
        except Exception:
            pass

    if not meta_addr:
        return {"status": "error", "message": "Metadata signature (FAB11BAF) with valid version offset could not be located in memory."}

    # Find the mapped memory range bounds containing this metadata start address
    found_range = None
    for r in all_ranges:
        start = int(r["start"], 16)
        end = int(r["end"], 16)
        if start <= meta_addr < end:
            found_range = r
            break

    if not found_range:
        return {"status": "error", "message": "Could not identify mapped boundary bounds for metadata address."}

    start_addr = meta_addr
    end_addr = int(found_range["end"], 16)
    size = end_addr - start_addr

    # Hard cap size to prevent leaks if memory segment is excessively large
    size_limit = 100 * 1024 * 1024
    if size > size_limit:
        end_addr = start_addr + size_limit
        size = size_limit

    print(f"[Quick Metadata Signature Dump] Mapped Range: {hex(start_addr)} - {hex(end_addr)} (Size: {size / (1024*1024):.2f}MB) to {output_path}")

    dest_file = pathlib.Path(output_path)
    dest_file.parent.mkdir(parents=True, exist_ok=True)

    chunk_size = 4 * 1024 * 1024
    bytes_written = 0

    try:
        with open(dest_file, "wb") as f:
            for offset in range(0, size, chunk_size):
                curr_size = min(chunk_size, size - offset)
                curr_addr = hex(start_addr + offset)
                chunk = rpc.dump_memory_range(curr_addr, curr_size)
                f.write(bytes(chunk))
                bytes_written += len(chunk)
        return {
            "status": "success",
            "message": "Successfully located and dumped metadata range directly to host.",
            "start_address": hex(start_addr),
            "end_address": hex(end_addr),
            "bytes_written": bytes_written
        }
    except Exception as e:
        return {"status": "error", "message": f"Failed to dump metadata range: {str(e)}"}



