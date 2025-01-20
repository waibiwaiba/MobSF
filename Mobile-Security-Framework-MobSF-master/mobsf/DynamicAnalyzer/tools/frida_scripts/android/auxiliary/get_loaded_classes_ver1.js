Java.perform(function() {
    var classes = Java.enumerateLoadedClassesSync();
    classes.forEach(function(aClass) {
        try {
            // 格式化类名
            var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
            send('[AUXILIARY] Class: ' + className);

            // 尝试获取类的方法
            try {
                var hook = Java.use(className);
                var methods = hook.class.getDeclaredMethods();
                hook.$dispose;

                // 输出所有方法
                methods.forEach(function(method) {
                    send('[AUXILIARY] Method: ' + method);
                });
            } catch (err) {
                send('[AUXILIARY] Error getting methods for class ' + className + ': ' + err);
            }
        } catch (err) {
            send('[AUXILIARY] Error processing class ' + aClass + ': ' + err);
        }
    });
});
