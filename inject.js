//  HOOK �б�
//      module  ģ������
//      func    �������� module ���벻Ϊ��
//      address ��ַ��������ڣ��� module ����Ϊ��
//      offset  ƫ�ƣ�������ڣ��� module ���벻Ϊ��
//      pre     Pre �ص�
//      post    post �ص�
//
//  ��� func �� offset ͬʱ���ڣ��� func ����
//  ��� module Ϊ�ղ��� address ҲΪ�գ�ʧ��
//
//  ʹ�÷������������ module_function �ṹ
//  ����дģ����������дҪHOOK�ĺ�����
//  �����д�����ؼ��ĺ�����Pre �� Post
//      Pre ����������������һ���� args ������������ Arg ����
//                      �ڶ���������������Ĭ�ϲ��� this ���ڲ������˼Ĵ�����Ϣ��
//      Post �����õõ���Ҳ��һ������ ����ֵ
//
//  Ψһ��ȷ����������ǿ����Ż����������£���ǰģ���������⣬�����Ƿ�����ȷ����
//  https://frida.re/docs/javascript-api/
var module_function_windows = [
/******************************************************************************
//  CreateFileW ʾ��
{'global': {}, 'module': 'kernelbase.dll', 'func': 'CreateFileW',
    //  https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi
    //  https://docs.microsoft.com/en-us/windows/win32/fileio/creating-and-opening-files
    //  �������������ܲ���ȷ����Ϊ����û���ñ�׼��ʽȡ����������
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
        //  �������������ַ
        module_function_windows[1].global[this.context.ebp] = this.context.rcx
    },
    'post': function (return_value) {
        //  �������ص�ʱ�򣬸���������������ַ
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
//  GetWindowTextA �ٳַ���ֵʾ��
{'global': {}, 'module': 'user32.dll', 'func': 'GetWindowTextA',
    'pre': function (args) {
        console.log('[+] Called GetWindowTextA');
        console.log('Context  : ' + JSON.stringify(this.context));
        //  �������������ַ
        module_function_windows[1].global[this.context.ebp] = args[1];
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
    },
    'post': function (return_value) {
        //  �������ص�ʱ�򣬸���������������ַ
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

//  HOOK ʾ��
{'global': {}, 'module': '', 'address': 0, 'pre': null, 'post': null},
{'global': {}, 'module': '', 'offset': 0, 'pre': null, 'post': null},
{'global': {}, 'module': '', 'func': '', 'pre': null, 'post': null}
];

//  HOOK �б�
//      class   ������
//      init    ��ʼ���ҹ�����
//      object  Ŀ�������
//
//  ����������class �� init ���������
//      �ڲ��߼�ͨ�� class ���ҵ���Ӧ�Ķ���
//      Ȼ����� init �������������
//      ����ڲ��Լ�������ص��߼���Ȼ���˳�
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
        //  Dll ע��ʾ��
        //var inj = RunInjectDll("D:\\TestDir\\VS2022\\VS2022Test\\x64\\Release\\Test054_DllInjectDll.dll", true);
        //console.log('inject = ' + inj);
    }
};

