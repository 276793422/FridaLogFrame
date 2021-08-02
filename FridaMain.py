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

JsShell = """

//  把数据发回给远程 Python
function NotifyRemotePython(payload, data_point, data_length) {
    if (data_point.isNull())
        return;
    var buf = data_point.readByteArray(data_length);
    send(payload, buf);
}
function CreateHijack() {
    for (var i in module_function) {
        var node = module_function[i]
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
            baseAddr = Module.findBaseAddress(node.module);
            if (node.func != undefined && node.func != null && node.func != '') {
                //  如果函数名存在，并且有效，拿函数名作为地址
                methodAddr = Module.getExportByName(node.module, node.func);
            } else if (node.offset != undefined && node.offset != 0) {
                //  如果函数名不存在，但是偏移存在，则直接取模块地址加偏移
                methodAddr = baseAddr + node.offset;
            } else {
                //  如果函数名和偏移都不在，结束
                continue;
            }
            console.log(node.module + ' baseAddr: ' + baseAddr);
        }
        
        var pre_callback = node.pre;
        var post_callback = node.post;
        
        if (pre_callback == null && post_callback == null) {
            continue;
        }
        
        console.log('SendRequest at: ' + methodAddr);
        
        if (pre_callback == null) {
            pre_callback = function (args) {
            }
        }
        
        if (post_callback == null) {
            post_callback = function (retval) {
            }
        }

        Interceptor.attach(methodAddr, { onEnter: pre_callback, onLeave: post_callback } );
    }
}
CreateHijack();

"""


def on_message(message, data):
    print("Python [type : %s][payload : %s][%s] => %s" % (message['type'], message['payload'], message, data))


def main(target_process):
    session = frida.attach(target_process)
    with open("inject.js") as f:
        js_script = f.read() + JsShell
        script = session.create_script(js_script)
        script.on('message', on_message)
        script.load()
        print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
        sys.stdin.read()
        session.detach()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)














