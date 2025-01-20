Java.perform(function() {
    var classLoaders = [];
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            classLoaders.push(loader);
        },
        onComplete: function() {}
    });

    var loadedClasses = Java.enumerateLoadedClassesSync();
    loadedClasses.forEach(function(aClass) {
        try {
            var match = aClass.match(/[L](.*);/);
            if (match && match[1]) {
                var className = match[1].replace(/\//g, ".");
                if (className.length < 3 || className.includes("DexPathList")) {
                    send('[AUXILIARY] Skip Class: ' + className);
                    return;
                }
                send('[AUXILIARY] Class: ' + className);
                var hook = Java.use(className);
                var methods = hook.class.getDeclaredMethods();
                methods.forEach(function(method) {
                    send('[AUXILIARY] Method: ' + className + ' -> ' + method);
                });
                hook.$dispose();
            }
        } catch (err) {
            send('[AUXILIARY] Error processing class ' + aClass + ': ' + err);
        }
    });
});
