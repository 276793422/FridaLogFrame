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
//  key 字段用来存放当前节点的可预置索引，用来查找对应的global
//  global 字段用来存放当前节点的全局变量，用来保存所需的全局数据，主要是用来存放从 Pre 到 Post 流程之间的内容
//
//  唯一不确定的情况，是开启优化编译的情况下，当前模块的相关问题，参数是否能正确解析
//  https://frida.re/docs/javascript-api/
var module_function_windows = [
///******************************************************************************
//  GetWindowTextA 劫持返回值示例
{'enable' : false , 'key' : 'user32_GetWindowTextA' , 'global': {}, 'module': 'user32.dll', 'func': 'GetWindowTextA',
    'pre': function (args) {
        console.log('[+] Called GetWindowTextA');
        var params = this.context;
        var obj = GetContext(module_function_windows, 'user32_GetWindowTextA');

        //  保存输出参数地址
        console.log('Context  : ' + JSON.stringify(params));
        console.log('args[1]  : ' + args[1]);
        console.log('args[2]  : ' + args[2]);
        obj.global[params.ebp] = args[1];
    },
    'post': function (return_value) {
        //  函数返回的时候，覆盖这个输出参数地址
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
{'enable' : false , 'key' : 'kernelbase_readfile' , 'global': {}, 'module': 'kernelbase.dll', 'func': '_____ReadFile',
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

//  HOOK 示例
{'enable' : true , 'key' : '' , 'global': {}, 'module': '', 'address': 0, 'pre': null, 'post': null},
{'enable' : true , 'key' : '' , 'global': {}, 'module': '', 'offset': 0, 'pre': null, 'post': null},
{'enable' : true , 'key' : '' , 'global': {}, 'module': '', 'func': '', 'pre': null, 'post': null}
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
    {
        'enable' : true ,
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
    {
        'enable' : false ,
        'class': 'com.zui.continuity.board.util.LogUtils',
        'init': function (class_object){
            let LogUtils = class_object;
            console.log(`LogUtils is called : isDebug = ${LogUtils.LOG_INFO.value}`);
            LogUtils.LOG_INFO.value = true;
            console.log(`LogUtils is called : isDebug = ${LogUtils.LOG_INFO.value}`);
        },
        'object' : null
    },
    {'enable' : true , 'class': '', 'init': null, 'object' : null }
];

var module_run_event = {
    'pre' : function (system_env) {
        console.log(`call module run event pre  : ${system_env.system_type}`);
    },
    'post' : function (system_env) {
        console.log(`call module run event post : ${system_env.system_type}`);
        //  Dll 注入示例
        //var inj = RunInjectDll("D:\\Lenovo\\TestTools\\TestTools\\x64\\Release\\CameraTestModule.dll", false);
        //console.log('inject = ' + inj);
    }
};


//  console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));                              //java打印堆栈
//  console.log(' called from:\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n'); //SO打印堆栈
