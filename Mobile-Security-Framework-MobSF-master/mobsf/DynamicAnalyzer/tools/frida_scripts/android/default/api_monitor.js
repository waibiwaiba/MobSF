// MobSF Android API Monitor
// Inspired from: https://github.com/realgam3/ReversingAutomation/blob/master/Frida/Android-DynamicHooks/DynamicHooks.js
// Dynamically load API list from CSV file

var apis = [];
Java.performNow(function () {
    var Exception = Java.use('java.lang.Exception');
    var FileInputStream = Java.use('java.io.FileInputStream');
    var InputStreamReader = Java.use('java.io.InputStreamReader');
    var BufferedReader = Java.use('java.io.BufferedReader');
    var StringBuilder = Java.use('java.lang.StringBuilder');

    var filePath = "/data/local/tmp/hooked_api_list.csv"; // 自定义 API 列表文件路径
    var fileInputStream = FileInputStream.$new(filePath);
    var inputStreamReader = InputStreamReader.$new(fileInputStream);
    var bufferedReader = BufferedReader.$new(inputStreamReader);
    var stringBuilder = StringBuilder.$new();

    var line;
    while ((line = bufferedReader.readLine()) !== null) {
        stringBuilder.append(line).append("\n"); // 确保换行符正确添加
    }
    bufferedReader.close();

    // 解析 CSV 文件内容
    var csvContent = stringBuilder.toString().split("\n");
    var header = csvContent[0].split(","); // 获取表头
    var enabledIndex = header.indexOf("enabled");
    var classIndex = header.indexOf("class");
    var methodIndex = header.indexOf("method");
    var nameIndex = header.indexOf("name");
    var tagIndex = header.indexOf("tag");
    var descriptionIndex = header.indexOf("description");

    for (var i = 1; i < csvContent.length; i++) {
        var row = csvContent[i].split(",");
        if (row.length < 6) continue; // 跳过无效的行
        if (row[enabledIndex].toLowerCase() === "true") {  // 只监听 enabled 为 True 的 API
            var api = {
                id: row[0],  // 获取 id
                class: row[classIndex].trim(),  // 去除多余空格
                method: row[methodIndex].trim(),
                enabled: true,
                tag: row[tagIndex].trim() || "",  // 默认值为空
                name: row[nameIndex].trim() || "",  // 默认值为空
                description: row[descriptionIndex].trim() || ""  // 默认值为空
            };
            apis.push(api);
        }
    }

    send("[API Monitor] Loaded " + apis.length + " APIs from CSV.");
});

// 添加一个格式化时间的辅助函数（使用兼容的语法）
function formatDate(date) {
    function pad(num) {
        return (num < 10 ? '0' : '') + num;
    }
    
    function padMs(num) {
        if (num < 10) return '00' + num;
        if (num < 100) return '0' + num;
        return num;
    }
    
    var year = date.getFullYear();
    var month = pad(date.getMonth() + 1);
    var day = pad(date.getDate());
    var hours = pad(date.getHours());
    var minutes = pad(date.getMinutes());
    var seconds = pad(date.getSeconds());
    var milliseconds = padMs(date.getMilliseconds());
    
    return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds + '.' + milliseconds;
}


// Dynamic Hooks
function hook(api, callback) {
    var Exception = Java.use('java.lang.Exception');
    var toHook;
    try {
        var clazz = api.class;
        var method = api.method;
        var name = api.name;
        try {
            if (api.target && parseInt(Java.androidVersion, 10) < api.target) {
                // send('[API Monitor] Not Hooking unavailable class/method - ' + clazz + '.' + method)
                return
            }
            // Check if class and method is available
            toHook = Java.use(clazz)[method];
            if (!toHook) {
                send('[API Monitor] Cannot find ' + clazz + '.' + method);
                return
            }
        } catch (err) {
            send('[API Monitor] Cannot find ' + clazz + '.' + method);
            return
        }
        var overloadCount = toHook.overloads.length;
        for (var i = 0; i < overloadCount; i++) {
            toHook.overloads[i].implementation = function () {
                var argz = [].slice.call(arguments);
                // Call original function
                var retval = this[method].apply(this, arguments);
                if (callback) {
                    var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
                    var message = {
                        // LX
                        // 我怀疑在这里加时间戳就可以了
                        time: formatDate(new Date()),  // 添加时间戳字段
                        name: name,
                        class: clazz,
                        method: method,
                        arguments: argz,
                        result: retval ? retval.toString() : null,
                        calledFrom: calledFrom
                    };
                    retval = callback(retval, message);
                }
                return retval;
            }
        }
    } catch (err) {
        send('[API Monitor] - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
    }
}

Java.performNow(function () {
    apis.forEach(function (api, _) {
        hook(api, function (originalResult, message) {
            /*if (!message.name.includes('Database') &&
                !message.name.includes('Crypto - Hash') &&
                !message.name.includes('File IO - Shared Preferences') &&
                !message.name.includes('File IO') &&
                !message.name.includes('IPC')) {
            */
            message.returnValue = originalResult
            if (originalResult && typeof originalResult === 'object') {
                var s = [];
                for (var k = 0, l = originalResult.length; k < l; k++) {
                    s.push(originalResult[k]);
                }
                message.returnValue = '' + s.join('');
            }
            if (!message.result)
                message.result = undefined
            if (!message.returnValue)
                message.returnValue = undefined
            var msg = 'MobSF-API-Monitor: ' + JSON.stringify(message);
            send(msg + ',');
            return originalResult;
        });
    });
});
