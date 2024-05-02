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
/*
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
*/
/*
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
*/
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
{'global': {}, 'module': 'GameAssembly.dll', 'offset': 0x014BDB50,
	'pre': function (args) {
        //console.log('[+] call pre  UnityEngine.Input::GetKeyDownInt(UnityEngine.KeyCode)');
        module_function_windows[1].global[this.context.ebp] = this.context.rcx;
    },
	'post': function (return_value) {
		if (return_value == 0) {
			return;
		}
		console.log('[+] call post UnityEngine.Input::GetKeyDownInt(UnityEngine.KeyCode)');
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
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
		console.log('[+] call post UnityEngine.Input::GetKeyUpInt(UnityEngine.KeyCode)');
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
        console.log('return_value : ' + return_value);
	} },
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
        console.log('args[1]  : ' + module_function_windows[1].global[this.context.ebp]);
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
    { 'class': 'com.lenovo.nfsserver.prog.NFS3Prog', 'init': HookNFS3Prog, 'object' : null },
    { 'class': 'com.lenovo.nfsserver.utils.LogUtils', 'init': OpenNFSServerDebugger, 'object' : null },
    { 'class': '', 'init': null, 'object' : null }
];


function HookNFS3Prog(class_object){
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
}

function OpenNFSServerDebugger(class_object){
    let LogUtils = class_object;
    console.log(`LogUtils is called : isDebug = ${LogUtils.isDebug.value}`);
    LogUtils.isDebug.value = false;
    console.log(`LogUtils is called : isDebug = ${LogUtils.isDebug.value}`);
}

function DllInject(file_path) {
	const loadLibrary = new NativeFunction(Module.findExportByName("kernel32.dll", "LoadLibraryA"), 'pointer', ['pointer']);
	var myLibAddr = loadLibrary(file_path);
	if (myLibAddr == null)
	{
    	console.log(`Inject error = ${file_path}`);
	}
	else
	{
    	console.log(`Inject success = ${file_path}`);
	}
}
