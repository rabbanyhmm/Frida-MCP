// In-process memory search, manipulation, and Game Guardian wrapper engine
// Runs directly inside the target process context to ensure maximum performance.

var candidates = [];        // Active candidate addresses
var candidateValues = {};  // Address -> Previous value (string representation)
var searchType = "dword";
var frozenAddresses = {};
var freezeIntervalId = null;

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

// Enumerate memory ranges filtered by regions (Anonymous, Heap, Stack, Code)
function getFilteredRanges(regions) {
    var allRanges = Process.enumerateRanges({ protection: "rw-", coalesce: true });
    if (!regions || regions.length === 0) return allRanges;

    return allRanges.filter(function(range) {
        var name = range.file ? range.file.path.toLowerCase() : "";
        
        // Match GG Regions
        if (regions.indexOf("anon") !== -1 && !range.file) return true;
        if (regions.indexOf("stack") !== -1 && name.indexOf("[stack]") !== -1) return true;
        if (regions.indexOf("heap") !== -1 && (name.indexOf("[heap]") !== -1 || name.indexOf("dalvik") !== -1)) return true;
        if (regions.indexOf("code") !== -1 && range.file && (name.indexOf(".so") !== -1 || name.indexOf(".apk") !== -1 || name.indexOf(".jar") !== -1)) return true;
        
        return false;
    });
}

// RPC exports defining the full memory search agent api
rpc.exports = {
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
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function(address, size) {
                        candidates.push(address.toString());
                        candidateValues[address.toString()] = valStr;
                    },
                    onError: function(reason) {},
                    onComplete: function() {}
                });
            } catch (e) {}
        });

        Thread.sleep(0.1); // Yield to let Async scan collect
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
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function(address, size) {
                        matches.push(address);
                    },
                    onError: function() {},
                    onComplete: function() {}
                });
            } catch (e) {}
        });

        Thread.sleep(0.1);

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
        // On ARM, Thumb instructions must align properly
        Memory.patchCode(targetAddr, 4, function(code) {
            var writer = new ArmWriter(code);
            // Example NOP patch helper
            if (assemblyInstruction.toLowerCase() === "nop") {
                writer.putNop();
            } else {
                // Otherwise write hex equivalent of instruction if provided directly
                var bytes = valToBytes(assemblyInstruction, "hex");
                code.writeByteArray(Array.prototype.slice.call(bytes));
            }
            writer.flush();
        });
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
            var bytes = start.readByteArray(size);
            // Returns binary data as base64 or array of values
            return Array.prototype.slice.call(new Uint8Array(bytes));
        } catch (e) {
            throw new Error("Failed to read memory range: " + e.toString());
        }
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
                        Memory.scan(r.base, r.size, pattern, {
                            onMatch: function(address) {
                                candidates.push(address.toString());
                                candidateValues[address.toString()] = val.toString();
                            },
                            onError: function() {},
                            onComplete: function() {}
                        });
                    } catch (e) {}
                });
                Thread.sleep(0.1);
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
    }
};
