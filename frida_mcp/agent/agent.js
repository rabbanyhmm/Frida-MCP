// In-process memory search, manipulation, and Game Guardian wrapper engine
// Runs directly inside the target process context to ensure maximum performance.

var candidates = [];        // Active candidate addresses
var candidateValues = {};  // Address -> Previous value (string representation)
var searchType = "dword";
var frozenAddresses = {};
var freezeIntervalId = null;
var hookLogs = [];          // Hook event queue
var installedHooks = {};    // Address -> Interceptor listener

// Convert integer to hex string helper
function u32ToHex(val) {
    var h = val.toString(16);
    while (h.length < 8) h = "0" + h;
    return h;
}

// Convert data types to byte patterns
function valToBytes(valStr, type, xorKey) {
    var buf;
    var view;
    var xKey = xorKey ? parseInt(xorKey, 10) : 0;

    if (type === "byte" || type === "u8") {
        buf = new ArrayBuffer(1);
        view = new DataView(buf);
        view.setUint8(0, (parseInt(valStr, 10) ^ xKey) & 0xFF);
        return new Uint8Array(buf);
    } 
    
    if (type === "word" || type === "u16") {
        buf = new ArrayBuffer(2);
        view = new DataView(buf);
        view.setUint16(0, (parseInt(valStr, 10) ^ xKey) & 0xFFFF, true);
        return new Uint8Array(buf);
    } 
    
    if (type === "dword" || type === "u32" || type === "int") {
        buf = new ArrayBuffer(4);
        view = new DataView(buf);
        var targetVal = parseInt(valStr, 10);
        if (xKey !== 0) targetVal = targetVal ^ xKey;
        view.setInt32(0, targetVal, true);
        return new Uint8Array(buf);
    } 
    
    if (type === "qword" || type === "u64") {
        buf = new ArrayBuffer(8);
        view = new DataView(buf);
        var targetBig = BigInt(valStr);
        if (xKey !== 0) targetBig = targetBig ^ BigInt(xKey);
        view.setBigInt64(0, targetBig, true);
        return new Uint8Array(buf);
    } 
    
    if (type === "float" || type === "f32") {
        buf = new ArrayBuffer(4);
        view = new DataView(buf);
        view.setFloat32(0, parseFloat(valStr), true);
        var floatBytes = new Uint8Array(buf);
        if (xKey !== 0) {
            for (var i = 0; i < 4; i++) {
                floatBytes[i] ^= (xKey >> (i * 8)) & 0xFF;
            }
        }
        return floatBytes;
    } 
    
    if (type === "double" || type === "f64") {
        buf = new ArrayBuffer(8);
        view = new DataView(buf);
        view.setFloat64(0, parseFloat(valStr), true);
        var doubleBytes = new Uint8Array(buf);
        if (xKey !== 0) {
            for (var i = 0; i < 8; i++) {
                doubleBytes[i] ^= (xKey >> (i * 8)) & 0xFF;
            }
        }
        return doubleBytes;
    } 
    
    if (type === "utf8" || type === "string") {
        var utf8Bytes = [];
        for (var i = 0; i < valStr.length; i++) {
            var charcode = valStr.charCodeAt(i);
            if (charcode < 0x80) utf8Bytes.push(charcode ^ xKey);
            else if (charcode < 0x800) {
                utf8Bytes.push((0xc0 | (charcode >> 6)) ^ xKey);
                utf8Bytes.push((0x80 | (charcode & 0x3f)) ^ xKey);
            } else {
                utf8Bytes.push((0xe0 | (charcode >> 12)) ^ xKey);
                utf8Bytes.push((0x80 | ((charcode >> 6) & 0x3f)) ^ xKey);
                utf8Bytes.push((0x80 | (charcode & 0x3f)) ^ xKey);
            }
        }
        return new Uint8Array(utf8Bytes);
    } 
    
    if (type === "utf16") {
        var utf16Buf = new ArrayBuffer(valStr.length * 2);
        var utf16View = new DataView(utf16Buf);
        for (var i = 0; i < valStr.length; i++) {
            var val = valStr.charCodeAt(i);
            if (xKey !== 0) val = val ^ xKey;
            utf16View.setUint16(i * 2, val, true);
        }
        return new Uint8Array(utf16Buf);
    } 
    
    if (type === "hex") {
        var cleanHex = valStr.replace(/\s+/g, "");
        var hexBytes = new Uint8Array(cleanHex.length / 2);
        for (var i = 0; i < cleanHex.length; i += 2) {
            hexBytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16) ^ xKey;
        }
        return hexBytes;
    }
    
    throw new Error("Unsupported type for byte conversion: " + type);
}

function bytesToPattern(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i].toString(16);
        if (b.length < 2) b = "0" + b;
        hex.push(b);
    }
    return hex.join(" ");
}

function readAddress(addr, type) {
    var ptrAddr = ptr(addr);
    try {
        if (type === "byte" || type === "u8") return ptrAddr.readU8().toString();
        if (type === "word" || type === "u16") return ptrAddr.readU16().toString();
        if (type === "dword" || type === "u32" || type === "int") return ptrAddr.readS32().toString();
        if (type === "qword" || type === "u64") return ptrAddr.readS64().toString();
        if (type === "float" || type === "f32") return ptrAddr.readFloat().toString();
        if (type === "double" || type === "f64") return ptrAddr.readDouble().toString();
        if (type === "string" || type === "utf8") return ptrAddr.readUtf8String();
        if (type === "utf16") return ptrAddr.readUtf16String();
    } catch (e) {
        return null;
    }
    return null;
}

function writeAddress(addr, valStr, type) {
    var ptrAddr = ptr(addr);
    if (type === "byte" || type === "u8") ptrAddr.writeU8(parseInt(valStr, 10));
    else if (type === "word" || type === "u16") ptrAddr.writeU16(parseInt(valStr, 10));
    else if (type === "dword" || type === "u32" || type === "int") ptrAddr.writeS32(parseInt(valStr, 10));
    else if (type === "qword" || type === "u64") ptrAddr.writeS64(BigInt(valStr));
    else if (type === "float" || type === "f32") ptrAddr.writeFloat(parseFloat(valStr));
    else if (type === "double" || type === "f64") ptrAddr.writeDouble(parseFloat(valStr));
    else if (type === "utf8" || type === "string") ptrAddr.writeUtf8String(valStr);
    else if (type === "utf16") ptrAddr.writeUtf16String(valStr);
    else if (type === "hex") {
        var bytes = valToBytes(valStr, "hex");
        ptrAddr.writeByteArray(Array.prototype.slice.call(bytes));
    } else {
        throw new Error("Invalid write type: " + type);
    }
}

// Freeze/Lock Loop
function startFreezeLoop() {
    if (freezeIntervalId !== null) return;
    freezeIntervalId = setInterval(function() {
        var keys = Object.keys(frozenAddresses);
        if (keys.length === 0) {
            clearInterval(freezeIntervalId);
            freezeIntervalId = null;
            return;
        }
        keys.forEach(function(addr) {
            var item = frozenAddresses[addr];
            try {
                writeAddress(addr, item.value, item.type);
            } catch (e) {}
        });
    }, 100); // 100ms lock rate
}

function getFilteredRanges(regions) {
    var allRanges = Process.enumerateRanges({ protection: "r--", coalesce: false });
    if (!regions || regions.length === 0) return allRanges;

    return allRanges.filter(function(range) {
        var name = range.file ? range.file.path.toLowerCase() : "";
        
        // Skip native libraries to avoid translation page-fault crashes
        if (name.indexOf(".so") !== -1) return false;
        
        // Skip common translation runtime segments (Houdini/NDK translation buffers)
        if (name.indexOf("houdini") !== -1 || name.indexOf("dalvik") !== -1 || name.indexOf("/dev/ashmem") !== -1) return false;

        // Skip execute-only, JIT cache pages, and system library maps
        if (range.protection.indexOf("x") !== -1) return false;

        // Always include metadata file maps
        if (name.indexOf("global-metadata.dat") !== -1 || name.indexOf(".dat") !== -1) return true;

        // Match GG Regions
        if (regions.indexOf("anon") !== -1 && !range.file) {
            // Under simulation contexts, only permit anonymous segments if they are associated with metadata structure lookups
            if (name.indexOf("global-metadata.dat") !== -1 || name.indexOf(".dat") !== -1 || range.size == 55738368) return true;
            return false; // Restrict random anonymous scans completely to prevent crashes
        }
        if (regions.indexOf("stack") !== -1 && name.indexOf("[stack]") !== -1) return true;
        if (regions.indexOf("heap") !== -1 && name.indexOf("[heap]") !== -1) return true;
        if (regions.indexOf("code") !== -1 && range.file && (name.indexOf(".apk") !== -1 || name.indexOf(".jar") !== -1)) return true;
        
        return false;
    });
}

function isRangeReadable(base, size) {
    try {
        var pageSize = 4096;
        for (var offset = 0; offset < size; offset += pageSize) {
            base.add(offset).readU8();
        }
        if (size > 0) {
            base.add(size - 1).readU8();
        }
        return true;
    } catch (e) {
        return false;
    }
}

// RPC exports defining the full memory search agent api
rpc.exports = {
    allocateMemory: function(size) {
        try {
            var ptrAddr = Memory.alloc(size);
            if (typeof global.allocatedMemory === 'undefined') {
                global.allocatedMemory = [];
            }
            global.allocatedMemory.push(ptrAddr);
            return ptrAddr.toString();
        } catch (e) {
            return "ERROR: " + e.toString();
        }
    },

    protectMemory: function(addrStr, size, protection) {
        try {
            Memory.protect(ptr(addrStr), size, protection);
            return true;
        } catch (e) {
            return false;
        }
    },

    traversePointerChain: function(baseAddrStr, offsetsList) {
        var result = [baseAddrStr];
        try {
            var currentPtr = ptr(baseAddrStr);
            for (var i = 0; i < offsetsList.length; i++) {
                var offsetStr = offsetsList[i];
                var offset = (typeof offsetStr === "string" && offsetStr.startsWith("0x")) ? parseInt(offsetStr, 16) : parseInt(offsetStr, 10);
                currentPtr = currentPtr.add(offset).readPointer();
                result.push(currentPtr.toString());
            }
            return { status: "success", chain: result };
        } catch (e) {
            return { status: "error", error: e.toString(), chain: result };
        }
    },

    // 1. Initial Memory search supporting encryption, types, and wildcards
    searchValue: function(valStr, type, regions, xorKey) {
        candidates = [];
        candidateValues = {};
        searchType = type;
        var bytes = valToBytes(valStr, type, xorKey);
        var pattern = bytesToPattern(bytes);
        
        var ranges = getFilteredRanges(regions);
        ranges.forEach(function(range) {
            try {
                var base = range.base;
                var size = range.size;
                if (size <= 0 || base.isNull()) return;

                if (!isRangeReadable(base, size)) {
                    return; // Skip ranges containing uncommitted/protected guard pages (common on translation/JIT buffers)
                }

                var matches = Memory.scanSync(base, size, pattern);
                matches.forEach(function(match) {
                    candidates.push(match.address.toString());
                    candidateValues[match.address.toString()] = valStr;
                });
            } catch (e) {}
        });

        return candidates.length;
    },

    // 2. Refine existing candidates based on exact value or relation to previous value
    refineValue: function(valStr, mode) {
        // mode: "exact", "increased", "decreased", "changed", "unchanged", "greater", "less"
        var nextCandidates = [];
        var nextValues = {};

        for (var i = 0; i < candidates.length; i++) {
            var addr = candidates[i];
            var currentVal = readAddress(addr, searchType);
            if (currentVal === null) continue;

            var prevVal = candidateValues[addr];
            var match = false;

            if (!mode || mode === "exact") {
                match = (currentVal === valStr);
            } else if (mode === "changed") {
                match = (currentVal !== prevVal);
            } else if (mode === "unchanged") {
                match = (currentVal === prevVal);
            } else {
                // Numeric relative comparison
                var curNum = parseFloat(currentVal);
                var prevNum = parseFloat(prevVal);
                
                if (mode === "increased") match = (curNum > prevNum);
                else if (mode === "decreased") match = (curNum < prevNum);
                else if (mode === "greater") match = (curNum > parseFloat(valStr));
                else if (mode === "less") match = (curNum < parseFloat(valStr));
            }

            if (match) {
                nextCandidates.push(addr);
                nextValues[addr] = currentVal;
            }
        }

        candidates = nextCandidates;
        candidateValues = nextValues;
        return candidates.length;
    },

    // 3. Pointer Search inside candidate results
    searchPointers: function(limit) {
        var pointerCandidates = [];
        var targetRanges = Process.enumerateRanges({ protection: "r--", coalesce: true });
        var ptrSize = Process.pointerSize;

        // Collect matching candidate addresses as target pointers
        var targetSet = {};
        candidates.forEach(function(addr) {
            targetSet[addr] = true;
        });

        targetRanges.forEach(function(range) {
            try {
                var size = range.size;
                var base = range.base;
                // Scan memory pages for addresses pointing to our target list
                for (var offset = 0; offset < size - ptrSize; offset += ptrSize) {
                    var currentPtrVal = base.add(offset).readPointer().toString();
                    if (targetSet[currentPtrVal]) {
                        pointerCandidates.push({
                            pointerAddress: base.add(offset).toString(),
                            resolvesTo: currentPtrVal
                        });
                    }
                }
            } catch (e) {}
        });

        return pointerCandidates.slice(0, limit || 200);
    },

    // 4. Group Search (Multiple values close to each other)
    groupSearch: function(groupString, maxDistance, regions) {
        // groupString example: "100;50;99" (Dwords)
        candidates = [];
        candidateValues = {};
        
        var parts = groupString.split(";").map(function(p) { return parseInt(p, 10); });
        if (parts.length === 0) return 0;
        
        // Scan for the first item
        var firstVal = parts[0].toString();
        var bytes = valToBytes(firstVal, "dword");
        var pattern = bytesToPattern(bytes);
        var dist = maxDistance || 100;

        var ranges = getFilteredRanges(regions);
        var matches = [];

        ranges.forEach(function(range) {
            try {
                var matches = Memory.scanSync(range.base, range.size, pattern);
                matches.forEach(function(match) {
                    matches.push(match.address);
                });
            } catch (e) {}
        });

        // Verify group matches
        matches.forEach(function(addr) {
            var ok = true;
            for (var i = 1; i < parts.length; i++) {
                // Look nearby for subsequent values
                var foundNearby = false;
                var expectedVal = parts[i];
                // Check in window [-dist, +dist]
                for (var offset = -dist; offset <= dist; offset += 4) {
                    if (offset === 0) continue;
                    var checkAddr = addr.add(offset);
                    try {
                        if (checkAddr.readS32() === expectedVal) {
                            foundNearby = true;
                            break;
                        }
                    } catch (e) {}
                }
                if (!foundNearby) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                candidates.push(addr.toString());
                candidateValues[addr.toString()] = firstVal;
            }
        });

        return candidates.length;
    },

    // 5. Native Opcode patching / Code editing
    patchOpcode: function(addressStr, assemblyInstruction) {
        var targetAddr = ptr(addressStr);
        if (assemblyInstruction.toLowerCase() === "nop") {
            Memory.patchCode(targetAddr, 4, function(code) {
                var writer = new ArmWriter(code);
                writer.putNop();
                writer.flush();
            });
        } else {
            // Write hex bytes directly using Memory.protect for ultimate stealth and stability
            var bytes = valToBytes(assemblyInstruction, "hex");
            Memory.protect(targetAddr, bytes.length, 'rwx');
            targetAddr.writeByteArray(Array.prototype.slice.call(bytes));
        }
        return true;
    },

    // Candidate result tools
    getCandidates: function(limit) {
        var results = [];
        var max = Math.min(candidates.length, limit || 100);
        for (var i = 0; i < max; i++) {
            var addr = candidates[i];
            results.push({
                address: addr,
                value: readAddress(addr, searchType),
                type: searchType
            });
        }
        return {
            total: candidates.length,
            displayed: results.length,
            results: results
        };
    },

    writeValue: function(addr, valStr, type) {
        writeAddress(addr, valStr, type || searchType);
        return true;
    },

    editAllCandidates: function(valStr) {
        var count = 0;
        for (var i = 0; i < candidates.length; i++) {
            try {
                writeAddress(candidates[i], valStr, searchType);
                count++;
            } catch (e) {}
        }
        return count;
    },

    freezeValue: function(addr, valStr, type) {
        frozenAddresses[addr] = {
            value: valStr,
            type: type || searchType
        };
        startFreezeLoop();
        return true;
    },

    unfreezeValue: function(addr) {
        delete frozenAddresses[addr];
        return true;
    },

    clearSearch: function() {
        candidates = [];
        candidateValues = {};
        return true;
    },

    // Structured Hex View/Dump
    dumpMemoryRange: function(startStr, size) {
        var start = ptr(startStr);
        try {
            return start.readByteArray(size);
        } catch (e) {
            throw new Error("Failed to read memory range: " + e.toString());
        }
    },

    getRangesList: function(pattern) {
        var results = [];
        try {
            var file = new File("/proc/self/maps", "r");
            var line;
            var pat = pattern ? pattern.toLowerCase() : null;
            while ((line = file.readLine()) !== null) {
                var parts = line.trim().split(/\s+/);
                if (parts.length < 2) continue;
                
                var addrRange = parts[0].split("-");
                var perm = parts[1];
                var name = parts.slice(5).join(" ") || "";
                
                if (perm.indexOf("r") === -1) continue;

                if (pat) {
                    var nLower = name.toLowerCase();
                    if (pat.indexOf("*") !== -1) {
                        var suffix = pat.replace(/\*/g, "");
                        if (nLower.indexOf(suffix) === -1) continue;
                    } else {
                        if (nLower.indexOf(pat) === -1) continue;
                    }
                }

                results.push({
                    start: "0x" + addrRange[0],
                    end: "0x" + addrRange[1],
                    internalName: name
                });
            }
            file.close();
        } catch(e) {
            var allRanges = Process.enumerateRanges({ protection: 'r--', coalesce: false });
            allRanges.forEach(function(range) {
                var name = range.file ? range.file.path : "";
                if (pattern) {
                    var pat = pattern.toLowerCase();
                    var nLower = name.toLowerCase();
                    if (pat.indexOf("*") !== -1) {
                        var suffix = pat.replace(/\*/g, "");
                        if (nLower.indexOf(suffix) === -1) return;
                    } else {
                        if (nLower.indexOf(pat) === -1) return;
                    }
                }
                results.push({
                    start: range.base.toString(),
                    end: range.base.add(range.size).toString(),
                    internalName: name
                });
            });
        }
        return results;
    },

    getTargetInfo: function() {
        var mainModName = "unknown";
        try {
            mainModName = Process.mainModule ? Process.mainModule.name : "unknown";
        } catch(e) {}
        return {
            packageName: mainModName,
            label: mainModName,
            x64: Process.pointerSize === 8
        };
    },

    getValuesList: function(items) {
        var results = [];
        items.forEach(function(item) {
            var addr = item.address;
            var flag = item.flags;
            // Map GG flags to types: TYPE_BYTE = 1, TYPE_WORD = 2, TYPE_DWORD = 4, TYPE_QWORD = 64, TYPE_FLOAT = 16, TYPE_DOUBLE = 32
            var type = "dword";
            if (flag === 1) type = "byte";
            else if (flag === 2) type = "word";
            else if (flag === 4) type = "dword";
            else if (flag === 64) type = "qword";
            else if (flag === 16) type = "float";
            else if (flag === 32) type = "double";
            
            var val = readAddress(addr, type);
            var parsedVal = 0;
            if (val !== null) {
                if (type === "float" || type === "double") {
                    parsedVal = parseFloat(val);
                } else {
                    parsedVal = parseInt(val, 10);
                }
            }
            results.push({
                address: addr,
                value: parsedVal,
                flags: flag
            });
        });
        return results;
    },


    // Game Guardian JS Script runner engine context
    executeScriptJs: function(jsCode) {
        var gg = {
            searchNumber: function(val, type, regions, xorKey) {
                candidates = [];
                candidateValues = {};
                searchType = type;
                var bytes = valToBytes(val.toString(), type, xorKey);
                var pattern = bytesToPattern(bytes);
                var ranges = getFilteredRanges(regions);
                ranges.forEach(function(r) {
                    try {
                        var matches = Memory.scanSync(r.base, r.size, pattern);
                        matches.forEach(function(match) {
                            candidates.push(match.address.toString());
                            candidateValues[match.address.toString()] = val.toString();
                        });
                    } catch (e) {}
                });
                return candidates.length;
            },
            refineNumber: function(val, mode) {
                // Re-route to RPC method
                return rpc.exports.refineValue(val.toString(), mode);
            },
            getResults: function(limit) {
                var res = [];
                var count = Math.min(candidates.length, limit || 100);
                for (var i = 0; i < count; i++) {
                    res.push({ address: candidates[i], value: readAddress(candidates[i], searchType) });
                }
                return res;
            },
            editAll: function(val, type) {
                var count = 0;
                for (var i = 0; i < candidates.length; i++) {
                    try {
                        writeAddress(candidates[i], val.toString(), type || searchType);
                        count++;
                    } catch (e) {}
                }
                return count;
            },
            setValues: function(list) {
                list.forEach(function(item) {
                    try {
                        writeAddress(item.address, item.value.toString(), item.type || searchType);
                    } catch (e) {}
                });
            },
            freeze: function(addr, val, type) {
                frozenAddresses[addr] = { value: val.toString(), type: type || searchType };
                startFreezeLoop();
            },
            unfreeze: function(addr) {
                delete frozenAddresses[addr];
            }
        };

        try {
            var executionResult = (function() {
                return eval(jsCode);
            })();
            return {
                status: "success",
                result: executionResult !== undefined ? executionResult.toString() : "undefined"
            };
        } catch (e) {
            return {
                status: "error",
                message: e.toString(),
                stack: e.stack
            };
        }
    },

    registerHook: function(addressStr, valType, overrideValStr) {
        var targetAddr = ptr(addressStr);
        var addrKey = targetAddr.toString();

        if (installedHooks[addrKey]) {
            installedHooks[addrKey].detach();
            delete installedHooks[addrKey];
        }

        try {
            var listener = Interceptor.attach(targetAddr, {
                onEnter: function(args) {
                    this.argValues = [];
                    for (var i = 0; i < 8; i++) {
                        try {
                            this.argValues.push(args[i].toString());
                        } catch (e) {
                            this.argValues.push("error");
                        }
                    }
                    if (valType && valType.startsWith("set_arg")) {
                        var argIndex = parseInt(valType.substring(7), 10);
                        if (!isNaN(argIndex)) {
                            var overridePtr = ptr(overrideValStr === "true" || overrideValStr === "1" ? 1 : (overrideValStr === "false" || overrideValStr === "0" ? 0 : overrideValStr));
                            args[argIndex] = overridePtr;
                        }
                    }
                },
                onLeave: function(retval) {
                    var origRet = retval.toString();
                    var overridden = false;
                    
                    if (valType && !valType.startsWith("set_arg") && overrideValStr !== undefined && overrideValStr !== null && overrideValStr !== "") {
                        if (valType === "boolean" || valType === "bool") {
                            var boolVal = (overrideValStr.toLowerCase() === "true" || overrideValStr === "1");
                            retval.replace(ptr(boolVal ? 1 : 0));
                            overridden = true;
                        } else if (valType === "int" || valType === "dword" || valType === "u32") {
                            retval.replace(ptr(parseInt(overrideValStr, 10)));
                            overridden = true;
                        } else if (valType === "qword" || valType === "u64") {
                            retval.replace(ptr(overrideValStr));
                            overridden = true;
                        } else {
                            try {
                                retval.replace(ptr(overrideValStr));
                                overridden = true;
                            } catch(err) {}
                        }
                    }

                    if (hookLogs.length >= 100) {
                        hookLogs.shift();
                    }
                    hookLogs.push({
                        timestamp: new Date().toISOString(),
                        address: addrKey,
                        args: this.argValues.slice(0, 4), // preserve compact logging format
                        original_retval: origRet,
                        overridden_retval: overridden ? overrideValStr : null
                    });
                }
            });
            installedHooks[addrKey] = listener;
            return true;
        } catch (e) {
            throw new Error("Failed to attach Interceptor at " + addressStr + ": " + e.toString());
        }
    },

    getHookLogs: function() {
        var logs = hookLogs;
        hookLogs = [];
        return logs;
    },

    unhookFunction: function(addressStr) {
        if (installedHooks[addressStr]) {
            installedHooks[addressStr].detach();
            delete installedHooks[addressStr];
            return true;
        }
        return false;
    },

    traceCallTree: function(addressStr, depth) {
        var targetPtr = ptr(addressStr);
        var logs = [];
        var indent = "";
        
        try {
            Interceptor.attach(targetPtr, {
                onEnter: function(args) {
                    var currentDepth = this.depth || 0;
                    if (currentDepth > depth) return;
                    
                    logs.push({
                        type: "enter",
                        address: addressStr,
                        depth: currentDepth,
                        tid: this.threadId
                    });
                    
                    this.depth = currentDepth + 1;
                },
                onLeave: function(retval) {
                    if (this.depth !== undefined) {
                        this.depth--;
                        logs.push({
                            type: "leave",
                            address: addressStr,
                            depth: this.depth,
                            tid: this.threadId
                        });
                    }
                }
            });
            return { status: "success", message: "Call tree tracer attached" };
        } catch(e) {
            return { status: "error", error: e.toString() };
        }
    },

    hookModuleExports: function(moduleName) {
        var m = Process.findModuleByName(moduleName);
        if (!m) return { status: "error", error: "Module not found" };
        
        var count = 0;
        m.enumerateExports().forEach(function(exp) {
            if (exp.type === "function") {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            if (hookLogs.length < 500) {
                                hookLogs.push({
                                    type: "export_call",
                                    module: moduleName,
                                    name: exp.name,
                                    address: exp.address.toString()
                                });
                            }
                        }
                    });
                    count++;
                } catch(e) {}
            }
        });
        return { status: "success", hooked: count };
    },

    hookModuleImports: function(moduleName) {
        var m = Process.findModuleByName(moduleName);
        if (!m) return { status: "error", error: "Module not found" };
        
        var count = 0;
        m.enumerateImports().forEach(function(imp) {
            if (imp.type === "function" && imp.address) {
                try {
                    Interceptor.attach(imp.address, {
                        onEnter: function(args) {
                            if (hookLogs.length < 500) {
                                hookLogs.push({
                                    type: "import_call",
                                    module: moduleName,
                                    name: imp.name,
                                    address: imp.address.toString()
                                });
                            }
                        }
                    });
                    count++;
                } catch(e) {}
            }
        });
        return { status: "success", hooked: count };
    },

    enumerateThreads: function() {
        return Process.enumerateThreads().map(function(t) {
            return {
                id: t.id,
                state: t.state,
                context: t.context
            };
        });
    },

    backtraceThread: function(threadId) {
        try {
            var threads = Process.enumerateThreads();
            var targetThread = null;
            for (var i = 0; i < threads.length; i++) {
                if (threads[i].id === threadId) {
                    targetThread = threads[i];
                    break;
                }
            }

            if (!targetThread) return { status: "error", error: "Thread not found" };

            // For accurate backtracing we need the context, but Frida's Thread.backtrace
            // is best used inside an interceptor. If we have the context, we can try to walk it.
            var bt = Thread.backtrace(targetThread.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            
            var traces = bt.map(function(sym) {
                return {
                    address: sym.address.toString(),
                    name: sym.name,
                    moduleName: sym.moduleName,
                    fileName: sym.fileName,
                    lineNumber: sym.lineNumber
                };
            });

            return { status: "success", traces: traces };
        } catch (e) {
            return { status: "error", error: e.toString() };
        }
    },

    callNativeFunction: function(addressStr, returnType, argTypes, argsList) {
        try {
            var fPtr = ptr(addressStr);
            var f = new NativeFunction(fPtr, returnType, argTypes);
            var result = f.apply(null, argsList);
            // NativeFunction results could be native pointers, cast to string if needed
            if (result !== null && result !== undefined && typeof result.toString === 'function') {
                result = result.toString();
            }
            return { status: "success", result: result };
        } catch(e) {
            return { status: "error", error: e.toString() };
        }
    },

    invokeExportedFunction: function(moduleName, exportName, returnType, argTypes, argsList) {
        try {
            var m = Process.findModuleByName(moduleName);
            if (!m) return { status: "error", error: "Module not found" };
            
            var exp = null;
            var exports = m.enumerateExports();
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name === exportName) {
                    exp = exports[i];
                    break;
                }
            }
            if (!exp) return { status: "error", error: "Export not found" };
            
            var f = new NativeFunction(exp.address, returnType, argTypes);
            var result = f.apply(null, argsList);
            if (result !== null && result !== undefined && typeof result.toString === 'function') {
                result = result.toString();
            }
            return { status: "success", result: result };
        } catch (e) {
            return { status: "error", error: e.toString() };
        }
    },

    getModuleInfo: function(name) {
        var m = Process.findModuleByName(name);
        if (m) {
            return {
                base: m.base.toString(),
                size: m.size,
                name: m.name,
                path: m.path
            };
        }
        return { status: "error", error: "Module not found" };
    },

    dumpDex: function() {
        var results = [];
        Process.enumerateRanges('r--').forEach(function(range) {
            try {
                // "dex\n035\0" -> 64 65 78 0a 30 33 35 00
                Memory.scanSync(range.base, range.size, "64 65 78 0a 30 33 35 00").forEach(function(match) {
                    try {
                        var dexSize = Memory.readU32(match.address.add(0x20));
                        if (dexSize > 0 && dexSize < 100 * 1024 * 1024) { // Max 100MB sanity check
                            results.push({
                                address: match.address.toString(),
                                size: dexSize
                            });
                        }
                    } catch(e) {}
                });
            } catch (e) {}
        });
        return { status: "success", dexes: results };
    },

    enumerateModules: function() {
        return Process.enumerateModules().map(function(m) {
            return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
        });
    },

    getModuleExports: function(name) {
        var m = Process.findModuleByName(name);
        if (!m) return [];
        return m.enumerateExports().map(function(e) {
            return { type: e.type, name: e.name, address: e.address.toString() };
        });
    },

    getModuleImports: function(name) {
        var m = Process.findModuleByName(name);
        if (!m) return [];
        return m.enumerateImports().map(function(i) {
            return { type: i.type, name: i.name, module: i.module, address: i.address ? i.address.toString() : null };
        });
    },

    getModuleSymbols: function(name) {
        var m = Process.findModuleByName(name);
        if (!m) return [];
        return m.enumerateSymbols().map(function(s) {
            return { isGlobal: s.isGlobal, type: s.type, name: s.name, address: s.address.toString(), size: s.size };
        });
    },

    vaToRva: function(name, vaStr) {
        var m = Process.findModuleByName(name);
        if (!m) return { error: "Module not found" };
        try {
            var va = ptr(vaStr);
            var base = m.base;
            if (va.compare(base) < 0 || va.compare(base.add(m.size)) >= 0) {
                return { error: "Address not inside module bounds" };
            }
            var rva = va.sub(base);
            return { status: "success", rva: "0x" + rva.toString(16) };
        } catch (e) {
            return { error: e.toString() };
        }
    },

    quickHookOffsets: function(offsets, valType, overrideValStr, baseAddrStr) {
        var is32Bit = (Process.pointerSize === 4);
        var hookedCount = 0;

        // Python resolves the base address via ADB - no JS-side maps reading
        if (!baseAddrStr) {
            return 'ERROR: base address not provided - library may not be loaded yet';
        }

        var base = ptr(baseAddrStr);
        var overrideInt = (valType === 'boolean' || valType === 'bool')
            ? (overrideValStr === 'true' || overrideValStr === '1' ? 1 : 0)
            : null;

        offsets.forEach(function(offsetStr) {
            try {
                var offset = parseInt(offsetStr, 16);
                var addr = base.add(offset);
                if (is32Bit) addr = addr.add(1);
                Interceptor.attach(addr, {
                    onLeave: function(retval) {
                        if (overrideInt !== null) {
                            retval.replace(ptr(overrideInt));
                        } else {
                            try { retval.replace(ptr(overrideValStr)); } catch(e) {}
                        }
                    }
                });
                hookedCount++;
            } catch(e) {}
        });

        return 'hooked ' + hookedCount + '/' + offsets.length + ' offsets @ base=' + baseAddrStr;
    }
};
