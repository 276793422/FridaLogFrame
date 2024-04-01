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
        //  保存输出参数地址
        module_function[1].global[this.context.ebp] = args[1]
        console.log('args[1]  : ' + module_function[1].global[this.context.ebp]);
    },
    'post': function (return_value) {
        //  函数返回的时候，覆盖这个输出参数地址
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


