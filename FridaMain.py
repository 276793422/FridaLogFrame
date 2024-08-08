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

import os
import subprocess
import tempfile

import frida
import sys

'''
from dissect import cstruct

# 加载解析结构体头文件
cparser = cstruct.cstruct()
with open("wise_vector.h", 'r', encoding="utf-8") as f:
    cparser.load(f.read())

result = cparser.WISE_FEATURES_ISPACKED(data)
cstruct.dumpstruct(result)








'''

# JS 需要的一些内部库函数
JsShell_Base = """
//  获取当前时间，返回字符串，精确到毫秒
function GetCurrentTime() {
  const now = new Date();
  const year = now.getFullYear();
  const month = (now.getMonth() + 1).toString().padStart(2, '0');
  const day = now.getDate().toString().padStart(2, '0');
  const hours = now.getHours().toString().padStart(2, '0');
  const minutes = now.getMinutes().toString().padStart(2, '0');
  const seconds = now.getSeconds().toString().padStart(2, '0');
  const milliseconds = now.getMilliseconds().toString().padStart(3, '0');

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${milliseconds}`;
}

//  将字符数组转化成字符串
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

//  将UTF-8编码的字符串转成Unicode编码字符串
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

//  将Unicode编码的字符串转成字符串
function UnicodeByteToString(text) {
    return Memory.readUtf16String(text);
};

//  把数据发回给远程 Python
function NotifyRemotePythonInformation(payload, data_point, data_length) {
    if (data_point.isNull())
        return;
    var buf = data_point.readByteArray(data_length);
    send(payload, buf);
}

//  把数据发回给远程 Python，发送一个普通的 paylaod
function NotifyRemotePythonPayload(payload) {
    send(payload, '');
}

var function_list = {
    'RunInjectDll' : RunInjectDll,
    'GetCurrentTime' : GetCurrentTime,
    'Null' : null
};


"""

JsShell_Frida = JsShell_Base + """

//  获取指定key 的成员，方法有点笨
function GetContext(obj, key) {
    for (let i = 0; i < obj.length; i++) {
        if (obj[i].hasOwnProperty('key')) {
            if (obj[i].key == key) {
                return obj[i];
            }
        }
    }
    return null;
}

//  把内存 dump 输出
function OutputBuffer(buffer, _offset, _length) {
    return hexdump(buffer, {offset : Number(_offset), length : Number(_length)});
}

"""

# Windows 部分组件相关所需库函数，以及框架代码
JsShell_Windows = JsShell_Frida + """

//  加载指定DLL，执行相关内容
//  dll_path : 指定DLL路径
//  要求dll主函数快速退出，否则影响后续功能
function RunInjectDll(dll_path, unload = false) {
    let loadLibrary = new NativeFunction(Module.findExportByName("kernel32.dll", "LoadLibraryA"), 'pointer', ['pointer']);
    console.log(`Get Function LoadLibraryA = ${loadLibrary}`);
    let freeLibrary = new NativeFunction(Module.findExportByName("kernel32.dll", "FreeLibrary"), 'pointer', ['pointer']);
    console.log(`Get Function FreeLibrary = ${freeLibrary}`);
    let dllStr = Memory.allocUtf8String(dll_path);
    var myLibAddr = loadLibrary(dllStr);
    if (myLibAddr == 0) {
        console.log(`LoadLibraryA Call Error`);
        return false;
    } else {
        console.log(`LoadLibraryA Call Success = ${myLibAddr}`);
        if (unload == true) {
            var vBool = freeLibrary(myLibAddr);
            console.log(`unload = true, FreeLibrary = ${vBool} : ${myLibAddr} : ${dll_path}`);
        }
        return true;
    }
}

//  注册 Windows 部分所有拦截点
function CreateHijackWindows() {
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
        if (methodAddr == null) {
            console.log('attach error');
            continue;
        }
        Interceptor.attach(methodAddr, { onEnter: pre_callback, onLeave: post_callback } );
    }
}

//CreateHijackWindows();




"""

# Android 部分组件相关所需库函数，以及框架代码
JsShell_Android = JsShell_Frida + """

//  加载指定DLL，执行相关内容
//  dll_path : 指定DLL路径
//  要求dll主函数快速退出，否则影响后续功能
function RunInjectDll(dll_path, unload = false) {
    //  安卓侧目前不支持注入模块
    console.log(`not support in Android = ${loadLibrary}`);
    return false;
}

//  有针对性地一个点一个点做劫持点初始化，初始化函数内部一个点一个点判断是否是自己需要的劫持点
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

        console.log('        Init Save Object : ' + class_object)
        module_function_android[i].object = class_object;
        node.init(class_object);
    }
}

//  这里通过枚举方式获取对应函数并且劫持，直接Query 的方式大概率失败
function EnumPackageNameObject(class_name) {
    Java.perform(
        function(){
            Java.choose(
                "dalvik.system.PathClassLoader",
                {
                    onMatch: function(instance){
                        // console.log(instance)
                        var factory = Java.ClassFactory.get(instance)
                        try{
                            var varClassObject = factory.use(class_name)
                            if (varClassObject != null) {
                                console.log('    Find Class : ' + class_name)
                                CallHookFunction(class_name, varClassObject)
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

// 注册Android 部分所有劫持点
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

//CreateHijackAndroid();








"""

# 总入口，以及框架代码
JsShell_Entry = """
function RunCreateHijack(system_env) {
    console.log('==========');
    if (module_run_event.pre != null) {
        module_run_event.pre(system_env);
    }
    
    console.log('----------');
    if (system_env.system_type == 'windows') {
        CreateHijackWindows(system_env);
    }
    else if (system_env.system_type == 'android') {
        CreateHijackAndroid(system_env);
    }
    else {
        console.log('current system not support');
    }
    console.log('----------');
    
    if (module_run_event.post != null) {
        module_run_event.post(system_env);
    }
    console.log('==========');
}

RunCreateHijack(run_system_env);



"""


def output_engine_error(message):
    if 'type' in message:
        message_type = message['type']
        print("message_type : ", message_type)
    if 'description' in message:
        message_description = message['description']
        print("message_description : ", message_description)
    if 'stack' in message:
        message_stack = message['stack']
        print("message_stack : \n" + message_stack)
    if 'fileName' in message:
        message_file_name = message['fileName']
        print("message_fileName : ", message_file_name)
    if 'lineNumber' in message:
        message_line_number = message['lineNumber']
        print("message_lineNumber : ", message_line_number)
    if 'columnNumber' in message:
        message_column_number = message['columnNumber']
        print("message_columnNumber : ", message_column_number)

    return True


def on_message(message, data):
    bool_value = False
    # print("Python [type : %s][payload : %s][%s] => %s" % (message['type'], message['payload'], message, data))
    if isinstance(message, dict):
        if 'type' in message:
            message_type = message['type']

            if message_type == 'error':
                bool_value = output_engine_error(message)

    if bool_value is False:
        print("message : ", message)
        print("   data : ", data)


def MakeJsShellEnv(system_type):
    system_env_array = [
        "var run_system_env = {",
        "    'system_type' : '%s'," % system_type,
        "};",
    ]
    system_env = ""
    for item in system_env_array:
        system_env += item + "\n"
    return system_env


def run_windows(args):
    try:
        target_process = int(args)
    except ValueError:
        target_process = args

    js_shell_env = MakeJsShellEnv('windows')
    session = frida.attach(target_process)
    with open("inject.js") as f:
        js_script = f.read() + JsShell_Windows + JsShell_Android + js_shell_env + JsShell_Entry
        print("script ======> ", write_to_temp_file(js_script))
        script = session.create_script(js_script)
        script.on('message', on_message)
        script.load()
        print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
        run_wait_command()
        session.detach()
    pass


def run_android(args):
    # device = frida.get_usb_device()
    # pid = device.spawn([args])
    # device.resume(pid)
    # session = device.attach(pid)

    js_shell_env = MakeJsShellEnv('android')

    device = frida.get_usb_device()
    session = device.attach(args)
    with open("inject.js") as f:
        js_script = f.read() + JsShell_Windows + JsShell_Android + js_shell_env + JsShell_Entry
        print("script ======> ", write_to_temp_file(js_script))
        script = session.create_script(js_script)
        script.on('message', on_message)
        script.load()
        print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
        run_wait_command()
        session.detach()
    pass


def run_wait_command():
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


def android_install_server(path):
    if path is not None and path != "":
        adb_path = path
        if len(adb_path.split(" ")) != 1:
            adb_path = "\"" + adb_path + "\""
    else:
        return
    print("adb path : ", adb_path)

    current_dir = os.getcwd()
    server_path = current_dir + "\\Bin\\fsarm64"
    if len(current_dir.split(" ")) != 1:
        server_path = "\"" + server_path + "\""
    print("server path : ", server_path)

    run_command = f"{adb_path} push {server_path} /data/local/tmp"
    print("%s" % run_command)
    os.system(run_command)
    run_command = f"{adb_path} shell chmod 777 /data/local/tmp/fsarm64"
    print("%s" % run_command)
    os.system(run_command)
    pass


def android_run_server(path):
    # 输出结果
    print("目前只支持配置环境，不支持内部启动")
    print("用 root 权限，去设备里启动 /data/local/tmp/fsarm64 即可")
    print("adb 路径 ：", path)
    print("命令，按顺序敲：")
    print("\tadb shell")
    print("\tsu")
    print("\t/data/local/tmp/fsarm64")


def android_uninstall_server(path):
    if path is not None and path != "":
        adb_path = path
        if len(adb_path.split(" ")) != 1:
            adb_path = "\"" + adb_path + "\""
    else:
        return
    print("adb path : ", adb_path)
    run_command = f"{adb_path} shell rm /data/local/tmp/fsarm64"
    print("%s" % run_command)
    os.system(run_command)


def Main():
    if len(sys.argv) != 3:
        print("Usage: %s <os (windows/android)> <arges>" % __file__)
        print("Usage: %s windows <process name or PID>" % __file__)
        print("Usage: %s android <process name or PID>" % __file__)
        print("Usage: %s install <adb path>" % __file__)
        print("Usage: %s run <adb path>" % __file__)
        print("Usage: %s uninstall <adb path>" % __file__)
        print("只有调试 安卓 APP 时，才需要用到 install run uninstall 命令")
        sys.exit(1)

    try:
        os_platform = sys.argv[1]
        if os_platform.lower() == 'windows':
            run_windows(sys.argv[2])
        elif os_platform.lower() == 'android':
            run_android(sys.argv[2])
        elif os_platform.lower() == 'install':
            android_install_server(sys.argv[2])
        elif os_platform.lower() == 'run':
            android_run_server(sys.argv[2])
        elif os_platform.lower() == 'uninstall':
            android_uninstall_server(sys.argv[2])
    except Exception as e:
        print("Error: %s" % e)


if __name__ == '__main__':
    Main()
