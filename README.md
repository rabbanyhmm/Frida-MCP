# Dynamic Instrumenter & Memory Editor MCP Server

A Model Context Protocol (MCP) server that exposes advanced dynamic binary instrumentation, dynamic memory editing, pointer scanning, and automated scripting capabilities (JavaScript & Lua) to AI Agents and IDEs. 

This server integrates seamlessly with advanced AI systems such as **Antigravity**, **Cursor**, **Windsurf**, and **Claude Desktop**, allowing them to interactively inspect processes, search memory spaces, freeze variables, and hot-patch code in real-time.

---

## Capabilities

- **Memory Editing & Values Search**:
  - Scan target process memory for standard types: `byte`, `word`, `dword`, `qword`, `float`, `double`, `hex` patterns, and strings (`utf8` / `utf16`).
  - XOR encrypted search support with masks.
  - Scan region constraints: Anonymous maps, Stack, Heap, Dalvik, Code segments.
  - Fuzzy Search: Refine relative scans (`exact`, `changed`, `unchanged`, `increased`, `decreased`, `greater`, `less`).
- **Group & Nearby Scans**:
  - Locate multiple values separated by distance thresholds (e.g. `100;50;99`).
- **Pointer Scanning**:
  - Walk pointer paths to identify reference patterns pointing to target values.
- **Dynamic Variables Freezing**:
  - Lock variables in memory by writing values repeatedly on a 100ms interval loop.
- **Inline Binary Patching**:
  - Hot-patch executable code instructions (like NOP-ing checks) in-memory using `Memory.patchCode()`.
- **Script Run Engines**:
  - Exposes an embedded JavaScript script runner containing a simulated Game Guardian `gg` global class.
  - Supports executing standard Lua scripts on the host, bridged to the instrumentation agent.

---

## Installation

### Prerequisites
- Python 3.8 or later
- Target device must have `frida-server` running (or local process debugging enabled)

### Setup
Install the package in editable mode:
```bash
git clone <your-repository-url>
cd frida-mcp
pip install -e .
```

*To run Lua automation scripts, install with the optional Lua VM package:*
```bash
pip install -e ".[lua]"
```

---

## AI IDE and Client Integration

This server is designed to work with any MCP-compliant AI client. Below are configuration details for popular platforms:

### 1. Antigravity IDE
Add the server configuration under your MCP settings panel:
- **Type**: `command`
- **Name**: `frida-mcp`
- **Command**: `frida-mcp`

### 2. Cursor
In Cursor, navigate to **Settings** -> **Features** -> **MCP** and add a new agent:
- **Name**: `frida-mcp`
- **Type**: `command`
- **Command**: `frida-mcp`

### 3. Windsurf
In Windsurf, configure your global or workspace `mcp_config.json`:
```json
{
  "mcpServers": {
    "frida-mcp": {
      "command": "frida-mcp"
    }
  }
}
```

### 4. Claude Desktop
Add the following to your configuration file (Windows: `%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "frida-mcp": {
      "command": "frida-mcp"
    }
  }
}
```

---

## Exposed MCP Tools

### Process Control
- `list_devices`: View connected USB/local/remote devices.
- `list_processes`: Enumerate running processes.
- `locate_process`: Find process PIDs matching a search name.
- `spawn_program` / `resume_process` / `terminate_process`: Process lifecycle tools.

### Memory & Search
- `open_session`: Attach to a process and inject the instrumentation engine.
- `list_sessions`: View all open memory sessions (browser tab manager).
- `close_session`: Detach and clean up.
- `mem_search`: Initial memory scan by type.
- `mem_refine`: Filter scan list by value changes.
- `mem_pointer_search`: Find pointer addresses pointing to search targets.
- `mem_group_search`: Search for multiple values close to one another.
- `mem_get_candidates`: Retrieve values of matching addresses.
- `mem_write` / `mem_write_all`: Write values to single or all candidate results.
- `mem_freeze` / `mem_unfreeze`: Lock/unlock variables at specific addresses.
- `mem_patch_code`: Patch binary opcodes at runtime.
- `mem_dump_range`: Extract raw memory ranges as bytes.

### Persistent Offsets (Saved List)
- `saved_list_load`: Load saved offset database.
- `saved_list_add`: Save name, address, and type to local persistent config.
- `saved_list_remove`: Remove address from database.

### Custom Automation Scripts
- `execute_js_script`: Run JavaScript scripts (with global `gg` environment).
- `execute_lua_script`: Run Lua automation scripts.

---

## Scripting Environment Helpers

Scripts have access to the simulated `gg` scripting object:
- `gg.searchNumber(value, type, regions, xorKey)`
- `gg.refineNumber(value, mode)`
- `gg.getResults(limit)`
- `gg.editAll(value, type)`
- `gg.setValues(items)`
- `gg.freeze(address, value, type)`
- `gg.unfreeze(address)`

### Example Script (JS)
```javascript
// Search for variable value
var count = gg.searchNumber(100, "dword");
if (count > 0) {
    // Modify matches
    gg.editAll(9999, "dword");
}
```
