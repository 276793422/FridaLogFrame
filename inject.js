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
var module_function = [
{'global': null, 'module': 'user32.dll', 'func': 'SetWindowTextA', 'pre': function (args) {
        //console.log('[+] Called SetWindowTextA');
        //for (var i = 0; i < 2; i++)
        //{
        //    console.log('param    : '+i+': ' + args[i]);
        //}
        //console.log('Text     : ' + this.context.esp.add(0x8).readPointer().readCString())
        //console.log('Text     : ' + args[1].readCString())
        //console.log('this     : ' + JSON.stringify(this));
        //console.log('Context  : ' + JSON.stringify(this.context));
        //NotifyRemotePython('SetWindowTextA', args[1], args[1].readCString().length)
    }, 'post': function (return_value) {
        //console.log('[+] Returned from SetWindowTextA : ' + return_value);
        //console.log('');
    } },
{'global': null, 'module': 'user32.dll', 'func': 'GetWindowTextA', 'pre': function (args) {
        console.log('[+] Called GetWindowTextA');
        console.log('Context  : ' + JSON.stringify(this.context));
        //  �������������ַ
        module_function[1].global = args[1]
        console.log('args[1]  : ' + module_function[1].global);
    }, 'post': function (return_value) {
        //  �������ص�ʱ�򣬸���������������ַ
        console.log('args[1]  : ' + module_function[1].global);
        module_function[1].global.writeAnsiString("123456789");
        console.log('Text     : ' + this.context.esp.add(0x8).readPointer().readCString())
        console.log('this     : ' + JSON.stringify(this));
        console.log('Context  : ' + JSON.stringify(this.context));
        console.log('[+] Returned from GetWindowTextA : ' + return_value);
        console.log('');
    } },
{'global': null, 'module': '', 'address': 0, 'pre': null, 'post': null},
{'global': null, 'module': '', 'offset': 0, 'pre': null, 'post': null},
{'global': null, 'module': '', 'func': '', 'pre': null, 'post': null}
];

