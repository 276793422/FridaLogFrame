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
var module_function = [
{'module': 'user32.dll', 'func': 'SetWindowTextA', 'pre': function (args) {
        console.log('[+] Called SetWindowTextA');
        for (var i = 0; i < 2; i++)
        {
            console.log('param    : '+i+': ' + args[i]);
        }
        console.log('Text     : ' + this.context.esp.add(0x8).readPointer().readCString())
        //console.log('Text     : ' + args[1].readCString())

        console.log('this     : ' + JSON.stringify(this));
        console.log('Context  : ' + JSON.stringify(this.context));

        NotifyRemotePython('SetWindowTextA', args[1], args[1].readCString().length)
    }, 'post': function (retval, args) {
        console.log('[+] Returned from SetWindowTextA : ' + retval);
        console.log('');
    } },
{'module': '', 'address': 0, 'pre': null, 'post': null},
{'module': '', 'offset': 0, 'pre': null, 'post': null},
{'module': '', 'func': '', 'pre': null, 'post': null}
];

