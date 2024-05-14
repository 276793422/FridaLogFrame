//  HOOK 列表
//      module  模块名字
//      func    函数名， module 必须不为空
//      address 地址，如果存在，则 module 必须为空
//      offset  偏移，如果存在，则 module 必须不为空
//      pre     Pre 回调
//      post    post 回调
//
//  如果 func 和 offset 同时存在，则 func 优先
//  如果 module 为空并且 address 也为空，失败
//
//  使用方法，就是填充 module_function 结构
//  先填写模块名，再填写要HOOK的函数名
//  最后填写两个关键的函数，Pre 和 Post
//      Pre 函数有两个参数，一个是 args 参数，内容是 Arg 数组
//                      第二个参数是隐含的默认参数 this ，内部包含了寄存器信息等
//      Post 函数用得到的也就一个参数 返回值
//
//  唯一不确定的情况，是开启优化编译的情况下，当前模块的相关问题，参数是否能正确解析
//  https://frida.re/docs/javascript-api/
var module_function_windows = [
/******************************************************************************
//  CreateFileW 示例
{'global': {}, 'module': 'kernelbase.dll', 'func': 'CreateFileW',
    //  https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi
    //  https://docs.microsoft.com/en-us/windows/win32/fileio/creating-and-opening-files
    //  后三个参数可能不正确，因为这里没有用标准方式取后三个参数
    'pre': function (args) {
        console.log('[+] Called CreateFileW');
        console.log('\t arg 1 addr : ' + this.context.rcx);
        console.log('\t arg 1 : ' + UnicodeByteToString(this.context.rcx));
        console.log('\t arg 2 : ' + this.context.rdx);
        console.log('\t arg 3 : ' + this.context.r8);
        console.log('\t arg 4 : ' + this.context.r9);
        console.log('\t arg 5 : ' + this.context.r12);
        console.log('\t arg 6 : ' + this.context.rdi);
        console.log('\t arg 7 : ' + this.context.r13);
        //  保存输出参数地址
        module_function_windows[1].global[this.context.ebp] = this.context.rcx
    },
    'post': function (return_value) {
        //  函数返回的时候，覆盖这个输出参数地址
        console.log('\r ---->');
        console.log('\t arg 1 : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('[+] Returned from CreateFileW : ' + return_value);
        console.log('');
        delete module_function_windows[1].global[this.context.ebp];
    } },
******************************************************************************/

/******************************************************************************
{'global': {}, 'module': 'user32.dll', 'func': 'SetWindowTextA', 'pre': function (args) {
        //console.log('[+] Called SetWindowTextA');
        //for (var i = 0; i < 2; i++)
        //{
        //    console.log('param    : '+i+': ' + args[i]);
        //}
        //console.log('Text     : ' + this.context.esp.add(0x8).readPointer().readCString())
        //console.log('Text     : ' + args[1].readCString())
        //console.log('this     : ' + JSON.stringify(this));
        //console.log('Context  : ' + JSON.stringify(this.context));
        //NotifyRemotePythonInformation('SetWindowTextA', args[1], args[1].readCString().length)
    }, 'post': function (return_value) {
        //console.log('[+] Returned from SetWindowTextA : ' + return_value);
        //console.log('');
    } },
******************************************************************************/

///******************************************************************************
//  GetWindowTextA 劫持返回值示例
{'global': {}, 'module': 'user32.dll', 'func': 'GetWindowTextA',
    'pre': function (args) {
        console.log('[+] Called GetWindowTextA');
        console.log('Context  : ' + JSON.stringify(this.context));
        //  保存输出参数地址
        module_function_windows[1].global[this.context.ebp] = args[1];
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
    },
    'post': function (return_value) {
        //  函数返回的时候，覆盖这个输出参数地址
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        module_function_windows[1].global[this.context.ebp].writeAnsiString("123456789");
        console.log('this     : ' + JSON.stringify(this));
        console.log('Context  : ' + JSON.stringify(this.context));
        console.log('[+] Returned from GetWindowTextA : ' + return_value);
        console.log('');
        delete module_function_windows[1].global[this.context.ebp];
    } },
//******************************************************************************/

/*
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x014BDB90,
	'pre': function (args) {
        console.log('[+] call pre  UnityEngine.Input::GetKeyInt(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = args[1];
    },
	'post': function (return_value) {
		console.log('[+] call post UnityEngine.Input::GetKeyInt(UnityEngine.KeyCode)');
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
	} },
*/

/*
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x014BDB50,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetKeyDownInt(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('  -->');
		console.log(GetCurrentTime() + '[+] call post UnityEngine.Input::GetKeyDownInt(UnityEngine.KeyCode)');
		var key = module_function_windows[1].global[this.context.ebp];
        console.log('args[1]  : ' + key + ' >>>> return_value : ' + return_value);
        if (key == 0x64) return_value.replace(0x1);
        if (key == 0x77) return_value.replace(0x1);
	} },
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x014BDBD0,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetKeyUpInt(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('  ==>');
		console.log(GetCurrentTime() + '[+] call post UnityEngine.Input::GetKeyUpInt(UnityEngine.KeyCode)');
		var key = module_function_windows[1].global[this.context.ebp];
        console.log('args[1]  : ' + key + ' >>>> return_value : ' + return_value);
        if (key == 0x77) return_value.replace(0x1);
	} },
*/

/*
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x014BDCC0,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetMouseButtonDown(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('[+] call post UnityEngine.Input::GetMouseButtonDown(UnityEngine.KeyCode)');
		//console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
        //console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
	} },
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x014BDD00,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetMouseButtonUp(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('[+] call post UnityEngine.Input::GetMouseButtonUp(UnityEngine.KeyCode)');
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
	} },
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x01497BA0,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetMouseButtonUp(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('[+] call post LoadSceneAsyncNameIndexInternal_Injected 1');
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
	} },
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x01497C10,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetMouseButtonUp(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('[+] call post LoadSceneAsyncNameIndexInternal_Injected 2');
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
	} },
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x01497C70,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetMouseButtonUp(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('[+] call post LoadSceneAsyncNameIndexInternal_Injected 3');
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
	} },
*/

//  HOOK 示例
{'global': {}, 'module': '', 'address': 0, 'pre': null, 'post': null},
{'global': {}, 'module': '', 'offset': 0, 'pre': null, 'post': null},
{'global': {}, 'module': '', 'func': '', 'pre': null, 'post': null}
];

//  HOOK 列表
//      class   类名字
//      init    初始化挂钩函数
//      object  目标类对象
//
//  三个参数，class 和 init 均必须存在
//      内部逻辑通过 class 来找到对应的对象
//      然后调用 init 函数，传入对象
//      最后内部自己设置相关的逻辑，然后退出
//
//  https://frida.re/docs/javascript-api/
var module_function_android = [
    { 'class': 'com.lenovo.nfsserver.prog.NFS3Prog',
        'init': function (class_object) {
            let NFS3Prog = class_object;
            NFS3Prog["procedureGETATTR"].implementation = function () {
                console.log(`NFS3Prog.procedureGETATTR is called`);
                this["procedureGETATTR"]();
            };
            /*
            NFS3Prog["writeFattr3"].implementation = function (fileID, useCache) {
                console.log(`NFS3Prog.writeFattr3 is called: fileID=${fileID} , useCache=${useCache}`);
                this["writeFattr3"](fileID, useCache);
            };
            */
        } , 'object' : null },
    { 'class': 'com.lenovo.nfsserver.utils.LogUtils',
        'init': function (class_object){
            let LogUtils = class_object;
            console.log(`LogUtils is called : isDebug = ${LogUtils.isDebug.value}`);
            LogUtils.isDebug.value = false;
            console.log(`LogUtils is called : isDebug = ${LogUtils.isDebug.value}`);
        }, 'object' : null },
    { 'class': '', 'init': null, 'object' : null }
];


var module_run_event = {
    'pre' : function (system_env) {
        console.log(`call module run event pre  : ${system_env.system_type}`);
    },
    'post' : function (system_env) {
        console.log(`call module run event post : ${system_env.system_type}`);
        //  Dll 注入示例
        //var inj = RunInjectDll("D:\\TestDir\\VS2022\\VS2022Test\\x64\\Release\\Test054_DllInjectDll.dll", true);
        //console.log('inject = ' + inj);
    }
};

