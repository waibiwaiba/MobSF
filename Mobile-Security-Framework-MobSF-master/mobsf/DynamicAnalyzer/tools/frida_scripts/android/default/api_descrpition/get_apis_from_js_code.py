import csv
import re
js_code_hooked = """
var apis = [{
    class: 'android.os.Process',
    method: 'start',
    name: 'Process'
}, {
    class: 'android.app.ActivityManager',
    method: 'killBackgroundProcesses',
    name: 'Process'
}, {
    class: 'android.os.Process',
    method: 'killProcess',
    name: 'Process'
}, {
    class: 'java.lang.Runtime',
    method: 'exec',
    name: 'Command'
}, {
    class: 'java.lang.ProcessBuilder',
    method: 'start',
    name: 'Command'
}, {
    class: 'java.lang.Runtime',
    method: 'loadLibrary',
    name: 'Java Native Interface'
}, {
    class: 'java.lang.Runtime',
    method: 'load',
    name: 'Java Native Interface'
}, {
    class: 'android.webkit.WebView',
    method: 'loadUrl',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'loadData',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'loadDataWithBaseURL',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'addJavascriptInterface',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'evaluateJavascript',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'postUrl',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'postWebMessage',
    name: 'WebView',
    target: 6
}, {
    class: 'android.webkit.WebView',
    method: 'savePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'setHttpAuthUsernamePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'getHttpAuthUsernamePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'setWebContentsDebuggingEnabled',
    name: 'WebView'
}, {
    class: 'libcore.io.IoBridge',
    method: 'open',
    name: 'File IO'
},
{
    class: 'android.content.ContextWrapper',
    method: 'openFileInput',
    name: 'File IO'
}, {
    class: 'android.content.ContextWrapper',
    method: 'openFileOutput',
    name: 'File IO'
}, {
    class: 'android.content.ContextWrapper',
    method: 'deleteFile',
    name: 'File IO'
},

{
    class: 'android.content.ContextWrapper',
    method: 'openOrCreateDatabase',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'databaseList',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'deleteDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'execSQL',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'deleteDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'getPath',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insert',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insertOrThrow',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insertWithOnConflict',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'openDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'openOrCreateDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'query',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'queryWithFactory',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'rawQuery',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'rawQueryWithFactory',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'update',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'updateWithOnConflict',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'compileStatement',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'create',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'sendBroadcast',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'sendStickyBroadcast',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'startActivity',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'startService',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'stopService',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'registerReceiver',
    name: 'IPC'
}, {
    class: 'android.app.ContextImpl',
    method: 'registerReceiver',
    name: 'Binder'
}, {
    class: 'android.app.ActivityThread',
    method: 'handleReceiver',
    name: 'Binder'
}, {
    class: 'android.app.Activity',
    method: 'startActivity',
    name: 'Binder'
}, {
    class: 'javax.crypto.spec.SecretKeySpec',
    method: '$init',
    name: 'Crypto'
}, {
    class: 'javax.crypto.Cipher',
    method: 'doFinal',
    name: 'Crypto'
}, {
    class: 'java.security.MessageDigest',
    method: 'digest',
    name: 'Crypto - Hash'
}, {
    class: 'java.security.MessageDigest',
    method: 'update',
    name: 'Crypto - Hash'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getDeviceId',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSubscriberId',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getLine1Number',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkOperator',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkOperatorName',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimOperatorName',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getMacAddress',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getBSSID',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getIpAddress',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getNetworkId',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimCountryIso',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimSerialNumber',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkCountryIso',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getDeviceSoftwareVersion',
    name: 'Device Info'
}, {
    class: 'android.os.Debug',
    method: 'isDebuggerConnected',
    name: 'Device Info'
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstallerPackageName',
    name: 'Device Info'
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstalledApplications',
    name: 'Device Info'
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstalledModules',
    name: 'Device Info',
    target: 10,
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstalledPackages',
    name: 'Device Info'
}, {
    class: 'java.net.URL',
    method: 'openConnection',
    name: 'Network'
}, {
    class: 'org.apache.http.impl.client.AbstractHttpClient',
    method: 'execute',
    name: 'Network'
}, {
    class: 'com.android.okhttp.internal.huc.HttpURLConnectionImpl',
    method: 'getInputStream',
    name: 'Network'
}, {
    class: 'com.android.okhttp.internal.http.HttpURLConnectionImpl',
    method: 'getInputStream',
    name: 'Network'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findResource',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findResources',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findLibrary',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexFile',
    method: 'loadDex',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexFile',
    method: 'loadClass',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexClassLoader',
    method: '$init',
    name: 'Dex Class Loader'
}, {
    class: 'android.util.Base64',
    method: 'decode',
    name: 'Base64'
}, {
    class: 'android.util.Base64',
    method: 'encode',
    name: 'Base64'
}, {
    class: 'android.util.Base64',
    method: 'encodeToString',
    name: 'Base64'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'setComponentEnabledSetting',
    name: 'System Manager'
}, {
    class: 'android.app.NotificationManager',
    method: 'notify',
    name: 'System Manager'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'listen',
    name: 'System Manager'
}, {
    class: 'android.content.BroadcastReceiver',
    method: 'abortBroadcast',
    name: 'System Manager'
}, {
    class: 'android.telephony.SmsManager',
    method: 'sendTextMessage',
    name: 'SMS'
}, {
    class: 'android.telephony.SmsManager',
    method: 'sendMultipartTextMessage',
    name: 'SMS'
}, {
    class: 'android.content.ContentResolver',
    method: 'query',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'registerContentObserver',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'insert',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'delete',
    name: 'Device Data'
}, {
    class: 'android.accounts.AccountManager',
    method: 'getAccountsByType',
    name: 'Device Data'
}, {
    class: 'android.accounts.AccountManager',
    method: 'getAccounts',
    name: 'Device Data'
}, {
    class: 'android.location.Location',
    method: 'getLatitude',
    name: 'Device Data'
}, {
    class: 'android.location.Location',
    method: 'getLongitude',
    name: 'Device Data'
}, {
    class: 'android.media.AudioRecord',
    method: 'startRecording',
    name: 'Device Data'
}, {
    class: 'android.media.MediaRecorder',
    method: 'start',
    name: 'Device Data'
}, {
    class: 'android.os.SystemProperties',
    method: 'get',
    name: 'Device Data'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getInstalledPackages',
    name: 'Device Data'
}
];
"""



# /* {
#     // so much calls #LX
#     class: 'java.io.FileOutputStream',
#     method: 'write',
#     name: 'File IO'
# }, {
#     class: 'java.io.FileInputStream',
#     method: 'read',
#     name: 'File IO'
# }, */

# /*
# // crashes app on android 7 #LX
# {
#     class: 'android.app.SharedPreferencesImpl',
#     method: 'getString',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl',
#     method: 'contains',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl',
#     method: 'getInt',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl',
#     method: 'getFloat',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl',
#     method: 'getLong',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl',
#     method: 'getBoolean',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl',
#     method: 'getStringSet',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl$EditorImpl',
#     method: 'putString',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl$EditorImpl',
#     method: 'putStringSet',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl$EditorImpl',
#     method: 'putInt',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl$EditorImpl',
#     method: 'putFloat',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl$EditorImpl',
#     method: 'putBoolean',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl$EditorImpl',
#     method: 'putLong',
#     name: 'File IO - Shared Preferences'
# }, {
#     class: 'android.app.SharedPreferencesImpl$EditorImpl',
#     method: 'remove',
#     name: 'File IO - Shared Preferences'
# },
# */

# 读取JavaScript代码
js_code_commented= """
{
    class: 'java.io.FileOutputStream',
    method: 'write',
    name: 'File IO'
}, {
    class: 'java.io.FileInputStream',
    method: 'read',
    name: 'File IO'
},
{
    class: 'android.app.SharedPreferencesImpl',
    method: 'getString',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'contains',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getInt',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getFloat',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getLong',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getBoolean',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getStringSet',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putString',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putStringSet',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putInt',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putFloat',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putBoolean',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putLong',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'remove',
    name: 'File IO - Shared Preferences'
},
"""

# 提取API
def extract_apis(js_code):
    apis = []

    # 改进后的正则表达式
    api_pattern = re.compile(
        r'{[^}]*class\s*:\s*[\'"](.*?)[\'"],[^}]*method\s*:\s*[\'"](.*?)[\'"],[^}]*name\s*:\s*[\'"](.*?)[\'"][^}]*}'
    )
    
    matches = api_pattern.findall(js_code)
    for match in matches:
        api_class = match[0]
        api_method = match[1]
        api_name = match[2]
        
        api_entry = {"class": api_class, "method": api_method, "name": api_name}
        apis.append(api_entry)
    
    return apis

# 按字段排序
def sort_apis(api_list):
    return sorted(api_list, key=lambda x: (x["name"].lower(), x["class"].lower(), x["method"].lower()))

# 写入CSV
def write_to_csv(file_name, api_list):
    with open(file_name, "w", newline='', encoding="utf-8") as csvfile:
        fieldnames = ["name", "class", "method"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerows(api_list)

# 提取并处理API
apis = extract_apis(js_code_commented)
# LX
# apis = extract_apis(js_code_hooked)
# 排序API
sorted_apis = sort_apis(apis)

# 写入CSV文件
output_file = "apis.csv"
write_to_csv(output_file, sorted_apis)

print(f"CSV file generated: {output_file}")
