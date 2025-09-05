/**
 * # IDA脚本：导出函数列表
# 在IDA中运行此脚本生成函数映射

import idaapi
import idc
import json
import os

def export_functions(pth, append_mode=False, base_prefix='out', base_offset=0x0):
    functions = {}

    if append_mode and os.path.exists(pth):
        try:
            with open(pth, "r") as f:
                functions = json.load(f)
                if not isinstance(functions, dict):
                    print(f"警告: 文件 '{pth}' 内容不是有效的JSON对象。将进行覆盖。")
                    functions = {}
        except (json.JSONDecodeError, FileNotFoundError):
            print(f"警告: 无法解析 '{pth}' 或文件不存在。将创建新文件。")
            functions = {}
    
    # 获取所有函数
    for func_ea in Functions():
        func_name = get_func_name(func_ea)
        # 计算相对偏移
        base_addr = idaapi.get_imagebase()
        offset = base_offset + func_ea - base_addr
        
        # 也可以添加一些函数信息
        func_end = find_func_end(func_ea)
        functions[hex(offset)] = {
            "name": f'{func_name}',
            "start": hex(func_ea),
            "end": hex(func_end),
            "base_offset": hex(base_offset),
            "pos": base_prefix,
            "size": func_end - func_ea
        }
    with open(pth, "w") as f:
        json.dump(functions, f, indent=2)
 */


// Frida Stalker tracing so file with target file offset to check if
// rebuild so file is right 

let hasReplaced = false;
let printInstruction = false;

let blackList = [];

function print_stack(context){
    console.log("=== 调用栈开始 ===");
    var callStack = Thread.backtrace(context, Backtracer.FUZZY);

    for (var i = 0; i < callStack.length; i++) {
        var addr = callStack[i];
        console.log(addr)
        var module = Process.findModuleByAddress(addr);
        console.log(module)
        if(module){
            var moduleInfo = module ? module.name : "unknown";
            var offset = ptr(addr).sub(module.base);
            
            console.log("[" + i + "] " + addr + " " + moduleInfo + "!" + offset);
        }
    }
    console.log("=== 调用栈结束 ===");
}

function bypassAntiDebug() {
    // Hook ptrace
    var ptracePtr = Module.findGlobalExportByName("ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function(args) {
                console.log("[*] ptrace called, returning -1");
                this.replace_result = true;
            },
            onLeave: function(retval) {
                if (this.replace_result) {
                    retval.replace(-1);
                }
            }
        });
    }
}

var dumped = false;
function hook_so_open_file() {
    var pth = Module.findGlobalExportByName("open");
    Interceptor.attach(pth, {
        onEnter: function (args) {
            var pathPtr = args[0];
            // 打印文件路径和地址信息
            console.log("地址: " + pathPtr + " 路径: " + pathPtr.readCString());
            if(pathPtr.readCString().includes('dex')){
                // if (!dumped) {
                //     dumped = true;
                //     dump_so("libjiagu_64.so")
                // }
            }
            
        },
        onLeave: function (retval) {
            hook_proc_self_maps();
        }
    });
}

function hook_proc_self_maps() {
    if (hasReplaced) return;
    
    const openPtr = Module.findGlobalExportByName('open');
    if (!openPtr) {
        console.log("[-] open function not found");
        return;
    }
    
    console.log("[+] Found open function at: " + openPtr);
    
    const openOldPtr = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var fakePath = `/data/data/${apk_name}/maps`;
    var mapsFd = -1, statusFd = -1;
    var procMapPath = "";
    
    Interceptor.replace(openPtr, new NativeCallback(function (pathnameptr, flag) {
        var pathname = pathnameptr.readCString();
        // console.log("地址: " + pathnameptr + " 路径: " + pathnameptr.readCString());
        if (pathname.indexOf("maps") >= 0 || pathname.indexOf("status") >= 0) {
            console.log("[*] replaced open called with:", pathname);
        }
        
        if (pathname.indexOf("maps") >= 0) {
                console.log("[!] Redirecting maps access:", pathname, "->", fakePath);
                var filename = Memory.allocUtf8String(fakePath);
                mapsFd = openOldPtr(filename, flag);
                return mapsFd
        }
        if (pathname.indexOf("status") >= 0) {
            console.log("[!] Redirecting status access:", pathname, "->", fakePath);
            var filename = Memory.allocUtf8String(fakePath);
            return openOldPtr(filename, flag);
        }

        if (pathname.indexOf("dex") >= 0) {
            if (!dumped) {
                dumped = true;
                // print_stack();
                // dump_so("libjiagu_64.so")
            }
        }
        
        return openOldPtr(pathnameptr, flag);
    }, 'int', ['pointer', 'int']));
    
    hasReplaced = true;
    console.log("[+] Successfully hooked open function");
}

// var so_dlopen_count = 0;

// Hook dlopen functions
function hook_dlopen() {
    // bypassAntiDebug();
    var dlopenPtr = Module.findGlobalExportByName("dlopen");
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function (args) {
                var pathPtr = args[0];
                if (!!pathPtr) {
                    var path = pathPtr.readCString();
                    if (path && path.includes("jiagu")) {
                        console.log("[*] dlopen jiagu:", path);
                        this.is_hook_target = true
                        // so_dlopen_count ++;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_hook_target){
                    // hook_so_open_file();
                }
            }
        });
    }


    // var strncmpPtr = Module.findGlobalExportByName("strncmp")
    // if(strncmpPtr){
    //     Interceptor.attach(strncmpPtr, {
    //         onEnter: function (args) {

    //             this.s1 = args[0];
    //             this.s2 = args[1];
    //             this.n  = args[2].toInt32();
    
    //             if (this.s1.isNull() || this.s2.isNull() || this.n <= 0) return;
    
    //             // 限制最大读取长度，避免超大 n 导致卡顿
    //             var n = Math.min(this.n, 4096);
    
    //             // 最多读 n 个字节（遇到 \0 会提前停止）
    //             try{
    //                 this.str1 = this.s1.readUtf8String(n) || "";
    //                 this.str2 = this.s2.readUtf8String(n) || "";
    //                 console.log("[strncmp][hit] n=", n,
    //                             " s1=\""+ this.str1 + "\"",
    //                             " s2=\""+ this.str2 + "\"");
    //                 }catch (e){}
    //         },
    //         onLeave: function (retval) {
    //             console.log("[strncmp][ret] =", retval.toInt32());
    //             // console.log("[strncmp][ret] =", hexdump(this.context.x0, {offset: 0, length: 0x10, header: true, ansi: true}));
    //         }
    //     });
    // }
    
    var androidDlopenPtr = Module.findGlobalExportByName("android_dlopen_ext");
    if (androidDlopenPtr) {
        console.log("androidDlopenPtr: ", androidDlopenPtr)
        Interceptor.attach(androidDlopenPtr, {
            onEnter: function (args) {
                var pathPtr = args[0];
                if (pathPtr) {
                    var path = pathPtr.readCString();
                    if (path && path.includes("jiagu")) {
                        console.log("[*] android_dlopen_ext jiagu:", path);
                        this.isSoLoaded = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.isSoLoaded) {
                    // 只能用android_dlopen_ext来hook可以hook到，dlopen不行
                    // 可能和dlopen被用作自linker有关
                    trace_so();
                    hook_proc_self_maps()
                }
            }
        });
    }
}


// var isTraced = false
var apk_name = 'com.oacia.apk_protect'

function trace_so(){
    // if(isTraced) return;
    // isTraced = true
    // if(so_dlopen_count < 4 ){
    //     return;
    // }
    // 1. 获取目标SO文件的模块信息
    var targetModule = Process.getModuleByName("libjiagu_64.so"); // 替换为目标SO文件名
    console.log("[+] 目标模块:", targetModule.name);
    console.log("[+] 基地址:", targetModule.base);
    console.log("[+] 大小:", targetModule.size, "0x" + targetModule.size.toString(16));

    // 2. 加载IDA导出的函数映射
    var idaFunctions = {};
    // try {
    //     // 从手机读取IDA导出的函数列表
    //     var functionsData = File.readAllText(`/data/data/${apk_name}/functions.json`, "r");
    //     /**
    //      * idaFunctions = {
    //      *     "0x2980": {
    //      *         "name": "prefix_sub_2980",
    //      *         "start": "0x2980",
    //      *         "end": "0x2994",
    //      *         "base_offset": "0x0",
    //      *         "size": 20
    //      *     },
    //      * }
    //      */
    //     idaFunctions = JSON.parse(functionsData);
    //     console.log("[+] 已加载IDA函数映射:", Object.keys(idaFunctions).length, "个函数");
    // } catch (e) {
    //     console.log("[-] 无法加载函数映射文件:", e);
    //     console.log("[+] 使用以下命令推送文件:");
    //     console.log("    adb push functions.json /data/data/org.autojs.autojspro/");
    // }
    
    // 1. 根据偏移获取函数名
    function getFunctionName(addr, targetModule) {
        var offset = addr.sub(targetModule.base);
        var hexOffset = "0x" + offset.toString(16);
        
        // 先查找精确匹配
        if (idaFunctions[hexOffset] && blackList.indexOf(idaFunctions[hexOffset].name) === -1) {
            return [idaFunctions[hexOffset].name, 1, idaFunctions[hexOffset].pos];
        }
        
        // 查找最近的函数
        var bestMatch = null;
        var minDistance = 0x1000; // 最大距离4KB
        
        for (var key in idaFunctions) {
            var funcOffset = parseInt(key, 16);
            var distance = offset - funcOffset;
            
            if (distance >= 0 && distance < minDistance) {
                minDistance = distance;
                bestMatch = idaFunctions[key];
            }
        }
        
        if (bestMatch) {
            return [bestMatch.name + (minDistance > 0 ? "+0x" + minDistance.toString(16) : ""), 2, bestMatch.pos];
        }
        
        // 默认使用sub_格式
        return [DebugSymbol.fromAddress(addr).name, 0, "NaN"];
        // return ["", 0];
    }

    // 2. 创建Stalker实例并配置跟踪选项
    var stalker = Stalker;

    // 3. 更精确的跟踪 - 只跟踪目标SO内的执行
    function startPreciseTracing() {
        // isTraced = true
        console.log("[+] 开始详细跟踪目标SO...");
        stalker.exclude({
            "base": Process.getModuleByName("libc.so").base,
            "size": Process.getModuleByName("libc.so").size,});
        stalker.exclude({
            "base": Process.getModuleByName("libdl.so").base,
            "size": Process.getModuleByName("libdl.so").size,});
        stalker.follow(Process.getCurrentThreadId(), {
            events: {
                call:false,
                ret:false,
                exec:false,
                block:false,
                compile:false
            },
            onReceive: function(events) {
                // 解析 events ArrayBuffer
                const reader = Stalker.parse(events);
                
                while (reader.hasNext()) {
                    const event = reader.readNext();
                    
                    if (event.type === 'call') {
                        // 获取调用地址
                        const callAddress = event.location;
                        
                        // 尝试获取符号信息
                        const symbol = DebugSymbol.fromAddress(callAddress);
                        const moduleName = symbol.moduleName || "unknown";
                        const functionName = symbol.name || "unknown";
                        
                        // 过滤掉系统库的调用（可选）
                        if (moduleName.includes("libc.so") || 
                            moduleName.includes("libdl.so") ||
                            moduleName.includes("linker")) {
                            continue;
                        }
                        
                        // 输出调用信息
                        console.log(`[CALL] ${callAddress} -> ${moduleName}!${functionName}`);
                        
                        // 如果需要更详细的信息，可以获取调用栈
                        // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                        // backtrace.forEach(addr => {
                        //     const sym = DebugSymbol.fromAddress(addr);
                        //     console.log(`  ${addr} ${sym.moduleName}!${sym.name}`);
                        // });
                    }
                }
            },
            onCallSummary: function(summary) {
                // 可选：处理调用统计信息
                console.log("[+] Call summary:");
                Object.keys(summary).forEach(address => {
                    const count = summary[address];
                    const symbol = DebugSymbol.fromAddress(ptr(address));
                    console.log(`  ${address} (${symbol.name}): ${count} calls`);
                });
            },
            transform: function(iterator) {
                var instruction = iterator.next();
                var isInTargetModule = false;
                // var targetModule = Process.getModuleByName("libjiagu_64.so");
                targetModule = Process.getModuleByName("libjiagu_64.so");
                const canEmitNoisyCode = iterator.memoryAccess === 'open';
                do {
                    var addr = instruction.address;
                    isInTargetModule = (addr.compare(targetModule.base) >= 0 && 
                                     addr.compare(targetModule.base.add(targetModule.size)) < 0);
                    
                    if (isInTargetModule ) {
                        // var [symbolName, type, prefix] = getFunctionName(addr, targetModule);
                        // var offset = addr.sub(targetModule.base);
                        // if (type == 1) {
                        //     let pre_colored = prefix !== 'base'?`\x1b[31m${prefix}\x1b[0m`:prefix
                        //     let str = "[CALL] 符号: " + pre_colored + " " + symbolName + " 偏移: +0x" + offset.toString(16);
                        //     // let highlight_text = "sub_5F60";
                        //     // if(symbolName == highlight_text){
                        //     //     console.log(`\x1b[31m${str}\x1b[0m`);
                        //     // }else{
                        //         console.log(str);
                        //     // }
                        // }

                        // if (addr - targetModule.base >=0x5b48 && addr - targetModule.base <=0x5e2c) {
                            // iterator.putCallout(function(context) {
                            //     var currentAddr = context.pc;
                            //     var offset = currentAddr.sub(targetModule.base);
                            //     var [symbolName, type, prefix] = getFunctionName(currentAddr, targetModule);
                            //     // if (type == 1) {
                            //         console.log("[EXEC] PC: " + currentAddr + 
                            //                   " 偏移: +0x" + offset.toString(16) + 
                            //                   " 指令: " + Instruction.parse(currentAddr) +
                            //                   " 符号: " + symbolName);
                            //         // console.log("[EXEC] 符号: " + symbolName + " 偏移: +0x" + offset.toString(16));
                            //     // }
                            // });
                        // }

                        // inside target module addr range 
                        iterator.putCallout(function(context) {
                            var currentAddr = context.pc;
                            var offset = currentAddr.sub(targetModule.base);
                            var instruction = Instruction.parse(currentAddr);
                            let guess = '未知';

                            // dlopen function
                            if(offset == 0x3f8c){
                                    console.log('\n[ARM64寄存器状态]');
                                // 参数寄存器 X0-X7
                                // --- 1. 数据采集与预处理 ---
                                const regs = {};
                                for (let i = 0; i < 3; i++) {
                                    const regName = `x${i}`;
                                    const ptr = context[regName];
                                    try{
                                        const str = ptr.readCString();
                                        regs[regName] = { ptr, str, isStr: (str !== null) };
                                    }catch(e){
                                        console.log("error: ",e)
                                        regs[regName] = { ptr, str: null, isStr: false };
                                    }
                                }
                            
                                // --- 打印原始证据 ---
                                console.log('[RAW ARGUMENTS]');
                                console.log(`  x0: ${regs.x0.ptr} | as str: ${JSON.stringify(regs.x0.str)}`);
                                console.log('x0: ', hexdump(regs.x0.ptr,{
                                    offset: 0x0,
                                    length: 0x10,
                                    header: true,
                                    ansi: true
                                }));
                                console.log(`  x1: ${regs.x1.ptr} | as str: ${JSON.stringify(regs.x1.str)}`);
                                console.log(`  x2: ${regs.x2.ptr}`);
                                console.log('-'.repeat(70));
                            }
                            // // strcpy function
                            // if(offset == 0x4a9c){
                            //     console.log('instruction')
                            //     console.log(instruction)
                            //     var mnemonic = instruction.mnemonic;
                            //     var operands = instruction.operands;
                            //     console.log(DebugSymbol.fromAddress(ptr(operands[0].value)))
                            //     console.log(JSON.stringify(operands))

                            //     console.log('\n[ARM64寄存器状态]');
                            //     // 参数寄存器 X0-X7
                            //     // --- 1. 数据采集与预处理 ---
                            //     const regs = {};
                            //     for (let i = 0; i < 3; i++) {
                            //         const regName = `x${i}`;
                            //         const ptr = context[regName];
                            //         try{
                            //             const str = ptr.readCString();
                            //             regs[regName] = { ptr, str, isStr: (str !== null) };
                            //         }catch(e){
                            //             console.log("error: ",e)
                            //             regs[regName] = { ptr, str: null, isStr: false };
                            //         }
                            //     }
                            
                            //     // --- 打印原始证据 ---
                            //     console.log('[RAW ARGUMENTS]');
                            //     console.log(`  x0: ${regs.x0.ptr} | as str: ${JSON.stringify(regs.x0.str)}`);
                            //     console.log('x0: ', hexdump(regs.x0.ptr,{
                            //         offset: 0x0,
                            //         length: 0x10,
                            //         header: true,
                            //         ansi: true
                            //     }));
                            //     console.log(`  x1: ${regs.x1.ptr} | as str: ${JSON.stringify(regs.x1.str)}`);
                            //     console.log(`  x2: ${regs.x2.ptr}`);
                            //     console.log('-'.repeat(70));

                            // }
                            // // strcpy function return
                            // if(offset == 0x4aa0){
                            //     try {
                            //         const regs = context;
                            //         console.log('X0 (参数1):', hexdump(regs.x0,{
                            //             offset: 0x0,
                            //             length: 0x10,
                            //             header: true,
                            //             ansi: true
                            //         }));
                            //     } catch(e) {
                            //         console.log('返回值解析失败:', e.message);
                            //     }
                            // }
                            // var [symbolName, type, prefix] = getFunctionName(currentAddr, targetModule);
                            
                            // var mnemonic = instruction.mnemonic;
                            // var operands = instruction.operands;

                            // console.log(JSON.stringify(operands))

                            // if (mnemonic === 'bl' ||        // 函数调用
                            //     mnemonic === 'blr' ||       // 寄存器调用
                            //     mnemonic === 'b') {         // 分支跳转
                                
                            //     var targetAddr = null;
                            //     var targetInfo = "unknown";
                                
                            //     if (operands.length > 0) {
                            //         var firstOp = operands[0];
                                    
                            //         if (firstOp.type === 'imm') {
                            //             // 立即数地址: bl #0x7b03a66b10
                            //             targetAddr = ptr(firstOp.value);
                            //         } else if (firstOp.type === 'reg') {
                            //             // 寄存器调用: blr x1
                            //             var regName = firstOp.value; // "x1", "x2" 等
                            //             if (context[regName]) {
                            //                 targetAddr = context[regName];
                            //             }
                            //         }
                            //     }
                        });
                    }
                    
                    iterator.keep();
                } while ((instruction = iterator.next()) !== null);
            }
        });
    }

    // 自动开始跟踪
    startPreciseTracing();
}

function dump_so(so_name) {
    var libso = Process.getModuleByName(so_name);
    console.log("[name]:", libso.name);
    console.log("[base]:", libso.base);
    console.log("[size]:", ptr(libso.size));
    console.log("[path]:", libso.path);
    var file_path = "/data/data/" + apk_name + '/' + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
    var file_handle = new File(file_path, "wb");
    if (file_handle && file_handle != null) {
        Memory.protect(ptr(libso.base), libso.size, 'rwx');
        var libso_buffer = ptr(libso.base).readByteArray(libso.size);
        file_handle.write(libso_buffer);
        file_handle.flush();
        file_handle.close();
        console.log("[dump]:", file_path);
    }
}

Java.perform(function() {
    // hook_proc_self_maps();
    hook_dlopen();
});