// MobSF Android API Monitor
// Inspired from: https://github.com/realgam3/ReversingAutomation/blob/master/Frida/Android-DynamicHooks/DynamicHooks.js
var apis = [{
    class: 'android.os.Process',
    method: 'start',
    name: 'Process'
}, {
    class: 'android.app.ActivityManager',
    method: 'killBackgroundProcesses',
    name: 'Process'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimSerialNumber',
    name: 'Device Info'
}
];

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
