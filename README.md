# Frida MCP: Advanced Dynamic Reverse Engineering & Instrumentation

A Model Context Protocol (MCP) server that exposes advanced dynamic binary instrumentation, dynamic memory editing, pointer scanning, module analysis, and automated scripting capabilities (JavaScript & Lua) directly to AI Agents and IDEs. 

This server integrates seamlessly with advanced AI systems such as **Antigravity**, **Cursor**, **Windsurf**, and **Claude Desktop**, enabling them to autonomously act as a powerful Reverse Engineer. AI agents can interactively inspect processes, search memory spaces, hook and trace functions, traverse pointer chains, and hot-patch code in real-time.

---

## Capabilities & Architecture

Frida MCP operates out-of-process via an RPC bridge to an injected V8 JavaScript agent (`agent.js`), achieving native execution speed for memory scanning and instrumentation within the target process, while allowing high-level orchestration from the AI IDE.

### 1. Memory & Process Hacking
- **Memory Scanning & Filtering**: Fast scanning for `byte`, `word`, `dword`, `qword`, `float`, `double`, `hex` patterns, and strings. Supports XOR masks and region filters.
- **Dynamic Variable Freezing**: Lock variables in memory by writing values repeatedly on an interval loop.
- **Pointer Chain Traversal**: Automatically follow multi-level static offsets to dynamic heap structures.
- **Page Allocation & Protection**: Allocate new memory buffers dynamically and change memory page protections (e.g., `rwx`) at runtime.

### 2. Module & Symbol Analysis
- **Module Enumeration**: List all loaded binaries, libraries (`.so`, `.dll`, `.dylib`), and executables.
- **Exports & Imports Extraction**: Enumerate publicly exported API functions and imported dependencies for any loaded module.
- **Symbol Resolution**: Retrieve internal symbol tables and automatically convert Absolute Virtual Addresses (VA) to Relative Virtual Addresses (RVA) and vice versa, assisting in static analysis mapping.

### 3. Function Interception & Tracing
- **Function Hooking & Overrides**: Intercept calls to any memory address using `Interceptor.attach`, log arguments, and optionally overwrite the return value.
- **Inline Binary Patching**: Hot-patch machine code instructions in-memory (e.g., inserting `NOP`s).
- **Call Tree Tracing**: Track function execution depths and backtraces to understand complex game or application logic.
- **Mass API Hooking**: Automatically hook all exports or imports of an entire module simultaneously to instantly profile application behavior.

### 4. Advanced Automation & Scripting
- **Native Execution**: Cache and invoke dynamically exported APIs or arbitrary function addresses (`callNativeFunction`, `createNativeFunction`).
- **Native Callbacks**: Generate runtime native function pointers from JavaScript to intercept calls from the target application back into the agent.
- **JNI Tracing**: Dynamically enumerate and trace JNI method registrations (`RegisterNatives`) to intercept Android Java-to-Native crossings.
- **Target File Access**: Directly pull or push files via ADB integration, and extract DEX files right out of memory.
- **Embedded Script Runner**: Embeds a JavaScript script runner and a bridged Lua VM for executing legacy Game Guardian scripts (`gg` namespace).
- **Session Hot-Reloading**: Seamlessly swap and inject updated instrumentation scripts on-the-fly without restarting the process.
- **Quick Operations**: Minimize AI token usage by scanning and editing in one atomic MCP call.

### 5. Execution State & Thread Analysis
- **Thread Enumeration**: Analyze running thread states and CPU register contexts (`pc`, `sp`, `r0`-`r15`, etc.).
- **Accurate Stack Backtraces**: Interrogate individual threads to extract live execution paths and stack traces, resolving to debug symbols where available.

---

## Future Roadmap

The toolkit is continuously evolving. In the future, even more advanced reverse engineering capabilities will be added, including:
- **Advanced Context Manipulation**: Breakpoint injection, dynamic thread suspension, and register manipulation.
- **Advanced De-obfuscation**: Unpacking heavily packed libraries and bypassing aggressive anti-debug techniques (e.g., anti-ptrace, seccomp, root detection).
- **Network Traffic Tracing**: Native hooking for `recv`, `send`, and SSL/TLS crypto API interception.
- **File System & JNI Tracing**: Automatically logging Android/Linux OS file operations and JNI boundary crossings.

---

## Installation & Setup

### Prerequisites
- Python 3.8 or later
- Target device must have `frida-server` running (or local process debugging enabled via USB/ADB)

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
