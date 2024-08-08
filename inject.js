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
//  key �ֶ�������ŵ�ǰ�ڵ�Ŀ�Ԥ���������������Ҷ�Ӧ��global
//  global �ֶ�������ŵ�ǰ�ڵ��ȫ�ֱ������������������ȫ�����ݣ���Ҫ��������Ŵ� Pre �� Post ����֮�������
//
//  Ψһ��ȷ����������ǿ����Ż����������£���ǰģ���������⣬�����Ƿ�����ȷ����
//  https://frida.re/docs/javascript-api/
var module_function_windows = [
///******************************************************************************
//  GetWindowTextA �ٳַ���ֵʾ��
{'key' : 'user32_GetWindowTextA' , 'global': {}, 'module': 'user32.dll', 'func': 'GetWindowTextA',
    'pre': function (args) {
        console.log('[+] Called GetWindowTextA');
        var params = this.context;
        var obj = GetContext(module_function_windows, 'user32_GetWindowTextA');

        //  �������������ַ
        console.log('Context  : ' + JSON.stringify(params));
        console.log('args[1]  : ' + args[1]);
        console.log('args[2]  : ' + args[2]);
        obj.global[params.ebp] = args[1];
    },
    'post': function (return_value) {
        //  �������ص�ʱ�򣬸���������������ַ
        //console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
        var params = this.context;
        var obj = GetContext(module_function_windows, 'user32_GetWindowTextA');

        console.log('args[1]  : ' + obj.global[params.ebp]);
        console.log('Context  : ' + JSON.stringify(params));
        console.log('[+] Returned from GetWindowTextA : ' + return_value);

        obj.global[params.ebp].writeAnsiString("123456789");
        console.log('');
        delete obj.global[params.ebp];
    } },
{'key' : 'kernelbase_readfile' , 'global': {}, 'module': 'kernelbase.dll', 'func': 'ReadFile',
    'pre': function (args) {
        console.log('[+] Called KernelBase!ReadFile');
        var params = this.context;
        var obj = GetContext(module_function_windows, 'kernelbase_readfile');

        obj.global[params.rbp] = [params.rcx, params.rdx, params.r8, params.r9];
        console.log('args  : ' + obj.global[params.rbp]);
    },
    'post': function (return_value) {
        var params = this.context;
        var obj = GetContext(module_function_windows, 'kernelbase_readfile');

        var [hFile, lpBuffer, nNumberOfBytesToRead, pReadCount] = obj.global[params.rbp];
        delete obj.global[params.rbp];
        console.log('hFile                 : ' + hFile);
        console.log('lpBuffer              : ' + lpBuffer);
        console.log('nNumberOfBytesToRead  : ' + nNumberOfBytesToRead);
        console.log('pReadCount            : ' + pReadCount);
        console.log('[+] Returned from KernelBase!ReadFile : ' + return_value);

        var dmp = OutputBuffer(lpBuffer, 0, nNumberOfBytesToRead);
        console.log('hexdump : ');
        console.log(dmp);
        console.log('');
    }
},
//******************************************************************************/

//  HOOK ʾ��
{'key' : '' , 'global': {}, 'module': '', 'address': 0, 'pre': null, 'post': null},
{'key' : '' , 'global': {}, 'module': '', 'offset': 0, 'pre': null, 'post': null},
{'key' : '' , 'global': {}, 'module': '', 'func': '', 'pre': null, 'post': null}
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
    {
        'class': 'com.lenovo.hec.vault.api.FileStationManager',
        'init': function (class_object)
         {
            let FileStationManager = class_object;
            FileStationManager["handleHandshakeMessage"].implementation = function (deviceId, payload) {
                console.log(`handleHandshakeMessage : deviceId[${deviceId}] : payload[${payload}]`);
                this["handleHandshakeMessage"](deviceId, payload);
            };

            //NFS3Prog["writeFattr3"].implementation = function (fileID, useCache) {
            //    console.log(`NFS3Prog.writeFattr3 is called: fileID=${fileID} , useCache=${useCache}`);
            //    this["writeFattr3"](fileID, useCache);
            //};
        } ,
        'object' : null
    },
    /*
    {
        'class': 'com.zui.continuity.board.util.LogUtils',
        'init': function (class_object){
            let LogUtils = class_object;
            console.log(`LogUtils is called : isDebug = ${LogUtils.LOG_INFO.value}`);
            LogUtils.LOG_INFO.value = true;
            console.log(`LogUtils is called : isDebug = ${LogUtils.LOG_INFO.value}`);
        },
        'object' : null
    },
    */
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


//  console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));                              //java��ӡ��ջ
//  console.log(' called from:\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n'); //SO��ӡ��ջ
