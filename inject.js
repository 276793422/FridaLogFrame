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
{'global': {}, 'module': 'user32.dll', 'func': 'GetWindowTextA',
    'pre': function (args) {
        console.log('[+] Called GetWindowTextA');
        console.log('Context  : ' + JSON.stringify(this.context));
        //  �������������ַ
        module_function[1].global[this.context.ebp] = args[1]
        console.log('args[1]  : ' + module_function[1].global[this.context.ebp]);
    },
    'post': function (return_value) {
        //  �������ص�ʱ�򣬸���������������ַ
        console.log('args[1]  : ' + module_function[1].global[this.context.ebp]);
        module_function[1].global[this.context.ebp].writeAnsiString("123456789");
        console.log('this     : ' + JSON.stringify(this));
        console.log('Context  : ' + JSON.stringify(this.context));
        console.log('[+] Returned from GetWindowTextA : ' + return_value);
        console.log('');
        delete module_function[1].global[this.context.ebp];
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


