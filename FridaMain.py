# python3
# 作者        ：NemesisZoo
# 联系方式     ：276793422
# 创建日期     ：2021/7/21
# 文件名       ：FridaMain
# 文件简介     ：
# 文件说明     ：

"""

"""

from __future__ import print_function

import tempfile

import frida
import sys

'''
# pip install frida-tools
# pip install dissect.cstruct
from dissect import cstruct

# 加载解析结构体头文件
cparser = cstruct.cstruct()
with open("wise_vector.h", 'r', encoding="utf-8") as f:
    cparser.load(f.read())

result = cparser.WISE_FEATURES_ISPACKED(data)
cstruct.dumpstruct(result)








'''

JsShell_Base = """
function ByteToString(arr) {
    if(typeof arr === 'string') {
        return arr;
    }
    var str = '',
    _arr = arr;
    for(var i = 0; i < _arr.length; i++) {
        var one = _arr[i].toString(2),
            v = one.match(/^1+?(?=0)/);
        if(v && one.length == 8) {
            var bytesLength = v[0].length;
            var store = _arr[i].toString(2).slice(7 - bytesLength);
            for(var st = 1; st < bytesLength; st++) {
                store += _arr[st + i].toString(2).slice(2);
            }
            str += String.fromCharCode(parseInt(store, 2));
            i += bytesLength - 1;
        } else {
            str += String.fromCharCode(_arr[i]);
        }
    }
    return str;
}

function Utf8ByteToUnicodeStr(utf8Bytes){
    var unicodeStr ="";
    for (var pos = 0; pos < utf8Bytes.length;){
        var flag= utf8Bytes[pos];
        var unicode = 0 ;
        if ((flag >>>7) === 0 ) {
            unicodeStr+= String.fromCharCode(utf8Bytes[pos]);
            pos += 1;

        } else if ((flag &0xFC) === 0xFC ){
            unicode = (utf8Bytes[pos] & 0x3) << 30;
            unicode |= (utf8Bytes[pos+1] & 0x3F) << 24;
            unicode |= (utf8Bytes[pos+2] & 0x3F) << 18;
            unicode |= (utf8Bytes[pos+3] & 0x3F) << 12;
            unicode |= (utf8Bytes[pos+4] & 0x3F) << 6;
            unicode |= (utf8Bytes[pos+5] & 0x3F);
            unicodeStr+= String.fromCharCode(unicode) ;
            pos += 6;

        }else if ((flag &0xF8) === 0xF8 ){
            unicode = (utf8Bytes[pos] & 0x7) << 24;
            unicode |= (utf8Bytes[pos+1] & 0x3F) << 18;
            unicode |= (utf8Bytes[pos+2] & 0x3F) << 12;
            unicode |= (utf8Bytes[pos+3] & 0x3F) << 6;
            unicode |= (utf8Bytes[pos+4] & 0x3F);
            unicodeStr+= String.fromCharCode(unicode) ;
            pos += 5;

        } else if ((flag &0xF0) === 0xF0 ){
            unicode = (utf8Bytes[pos] & 0xF) << 18;
            unicode |= (utf8Bytes[pos+1] & 0x3F) << 12;
            unicode |= (utf8Bytes[pos+2] & 0x3F) << 6;
            unicode |= (utf8Bytes[pos+3] & 0x3F);
            unicodeStr+= String.fromCharCode(unicode) ;
            pos += 4;

        } else if ((flag &0xE0) === 0xE0 ){
            unicode = (utf8Bytes[pos] & 0x1F) << 12;;
            unicode |= (utf8Bytes[pos+1] & 0x3F) << 6;
            unicode |= (utf8Bytes[pos+2] & 0x3F);
            unicodeStr+= String.fromCharCode(unicode) ;
            pos += 3;

        } else if ((flag &0xC0) === 0xC0 ){ //110
            unicode = (utf8Bytes[pos] & 0x3F) << 6;
            unicode |= (utf8Bytes[pos+1] & 0x3F);
            unicodeStr+= String.fromCharCode(unicode) ;
            pos += 2;

        } else{
            unicodeStr+= String.fromCharCode(utf8Bytes[pos]);
            pos += 1;
        }
    }
    return unicodeStr;
}

//  把数据发回给远程 Python
function NotifyRemotePythonInformation(payload, data_point, data_length) {
    if (data_point.isNull())
        return;
    var buf = data_point.readByteArray(data_length);
    send(payload, buf);
}

function NotifyRemotePythonPayload(payload) {
    send(payload, '');
}




"""

JsShell_Windows = JsShell_Base + """
function CreateHijackWindows() {
    console.log('->');
    for (var i in module_function_windows) {
        var node = module_function_windows[i]
        var baseAddr = 0
        var methodAddr = 0
        if (node.module == '') {
            if (node.address == undefined || node.address == 0) {
                //  如果模块名不存在，地址又是空，不管了
                continue;
            }
            console.log('no module name :');
            //  如果模块为空，那么只有当地址不为空的时候，才认为有效
            methodAddr = node.address;
        } else {
            //  如果模块不为空，先取模块地址
            if (node.func != undefined && node.func != null && node.func != '') {
                //  如果函数名存在，并且有效，拿函数名作为地址
                methodAddr = Module.getExportByName(node.module, node.func);
            } else if (node.offset != undefined && node.offset != 0) {
                //  如果函数名不存在，但是偏移存在，则直接取模块地址加偏移
                //baseAddr = Module.findBaseAddress(node.module);
                //baseAddr = parseInt(baseAddr);
                //methodAddr = baseAddr + node.offset;
                //console.log(node.module + ' baseAddr: ' + baseAddr.toString(16) + ' : ' + baseAddr);
                var module = Process.getModuleByName(node.module);
                var addr = module.base.add(node.offset);
                methodAddr = new NativePointer(addr.toString());
            } else {
                //  如果函数名和偏移都不在，结束
                continue;
            }
        }
            
        var pre_callback = node.pre;
        var post_callback = node.post;
        
        if (pre_callback == null && post_callback == null) {
            continue;
        }
        
        if (pre_callback == null) {
                pre_callback = function (args) {
            }
        }
        
        if (post_callback == null) {
                post_callback = function (retval) {
            }
        }
        console.log('attach : ' + typeof methodAddr + ' : ' + methodAddr.toString(16) + ' : ' + methodAddr);
        if (methodAddr == NaN) {
            constole.log('attach error');
            continue;
        }
        Interceptor.attach(methodAddr, { onEnter: pre_callback, onLeave: post_callback } );
    }
}
CreateHijackWindows();









"""

JsShell_Android = JsShell_Base + """
function CallHookFunction(class_name, class_object) {
    for (var i in module_function_android) {
        var node = module_function_android[i]
        if (node.class == '') {
            continue;
        }
        if (node.hook == '') {
            continue;
        }
        if (node.init == null) {
            continue;
        }
        if (class_name != node.class) {
            continue;
        }

        module_function_android[i].object = class_object;
        node.init(class_object);
    }
}

function EnumPackageNameObject(class_name) {
    Java.perform(
        function(){
            Java.choose(
                "dalvik.system.PathClassLoader",
                {
                    onMatch: function(instance){
                        // console.log(instance)
                        // console.log(Java.ClassFactory)
                        var factory = Java.ClassFactory.get(instance)
                        try{
                            var NFS3ProgClass = factory.use(class_name)
                            if (NFS3ProgClass != null) {
                                CallHookFunction(class_name, NFS3ProgClass)
                                return "stop"
                            }
                        }catch(e){
                        }
                    },
                    onComplete:function(){
                        console.log("Done")
                    }
                }
            )
        }
    )
}

function CreateHijackAndroid() {
    for (var i in module_function_android) {
        var node = module_function_android[i]
        if (node.class == '') {
            continue;
        }
        if (node.hook == '') {
            continue;
        }
        if (node.init == null) {
            continue;
        }

        EnumPackageNameObject(node.class);
    }
}

CreateHijackAndroid();

"""


def OutputEngineError(message):
    if 'type' in message:
        message_type = message['type']
        print("message_type : ", message_type)
    if 'description' in message:
        message_description = message['description']
        print("message_description : ", message_description)
    if 'stack' in message:
        message_stack = message['stack']
        print("message_stack : ", message_stack)
    if 'fileName' in message:
        message_fileName = message['fileName']
        print("message_fileName : ", message_fileName)
    if 'lineNumber' in message:
        message_lineNumber = message['lineNumber']
        print("message_lineNumber : ", message_lineNumber)
    if 'columnNumber' in message:
        message_columnNumber = message['columnNumber']
        print("message_columnNumber : ", message_columnNumber)

    return True


def on_message(message, data):
    bool_value = False
    # print("Python [type : %s][payload : %s][%s] => %s" % (message['type'], message['payload'], message, data))
    if isinstance(message, dict):
        if 'type' in message:
            message_type = message['type']

            if message_type == 'error':
                bool_value = OutputEngineError(message)

    if bool_value is False:
        print("message : ", message)
        print("   data : ", data)


def RunWindows(args):
    try:
        target_process = int(args)
    except ValueError:
        target_process = args

    session = frida.attach(target_process)
    with open("inject.js") as f:
        js_script = f.read() + JsShell_Windows
        print("script ======> ", write_to_temp_file(js_script))
        script = session.create_script(js_script)
        script.on('message', on_message)
        script.load()
        print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
        RunWaitCommand()
        session.detach()


def RunAndroid(args):
    # device = frida.get_usb_device()
    # pid = device.spawn([args])
    # device.resume(pid)
    # session = device.attach(pid)

    device = frida.get_usb_device()
    session = device.attach(args)
    with open("inject.js") as f:
        js_script = f.read() + JsShell_Android
        print("script ======> ", write_to_temp_file(js_script))
        script = session.create_script(js_script)
        script.on('message', on_message)
        script.load()
        print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
        RunWaitCommand()
        session.detach()
    pass


def RunWaitCommand():
    while True:
        try:
            cmd = sys.stdin.read()
            cmd = cmd.replace('\n', '').replace('\r', '')
            print("cmd: %s" % cmd)
            if cmd == 'exit':
                break
            elif cmd == 'exit()':
                break
        except Exception as e:
            print("Error: %s" % e)
            break
    pass


def write_to_temp_file(content):
    # 创建一个临时文件，然后写入内容，最后返回文件名
    with tempfile.NamedTemporaryFile('w+t', delete=False) as f:
        f.write(content)
        return f.name


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: %s <os (windows/android)> <arges>" % __file__)
        print("Usage: %s windows <process name or PID>" % __file__)
        print("Usage: %s android <process name or PID>" % __file__)
        sys.exit(1)

    try:
        os_platform = sys.argv[1]
        if os_platform.lower() == 'windows':
            RunWindows(sys.argv[2])
        elif os_platform.lower() == 'android':
            RunAndroid(sys.argv[2])
    except Exception as e:
        print("Error: %s" % e)
