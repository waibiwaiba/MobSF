# API Documentation

本文件整理了从两个CSV文件中提取的API，并为每个API提供了简要的功能说明，便于理解和参考。

## 1.WebView APIs
与网页视图（WebView）相关的方法，用于加载和操作网页内容。

android.webkit.WebView.loadUrl

作用：加载指定的URL到WebView中。
android.webkit.WebView.loadData

作用：直接加载HTML数据字符串到WebView中显示。
android.webkit.WebView.loadDataWithBaseURL

作用：加载HTML数据字符串，并附加一个基准URL，用于解析相对路径资源。
android.webkit.WebView.addJavascriptInterface

作用：将一个Java对象注入到WebView中，使其能通过JavaScript调用。
android.webkit.WebView.evaluateJavascript

作用：在WebView中异步执行JavaScript代码，并获取结果。
android.webkit.WebView.postUrl

作用：以POST方式将数据提交到指定的URL。
android.webkit.WebView.postWebMessage

作用：向WebView发送消息，支持更高级的跨域通信。
android.webkit.WebView.savePassword

作用：保存用户的网页密码信息（已废弃，建议不要使用）。
android.webkit.WebView.setHttpAuthUsernamePassword

作用：设置HTTP身份验证的用户名和密码。
android.webkit.WebView.getHttpAuthUsernamePassword

作用：获取HTTP身份验证的用户名和密码。
android.webkit.WebView.setWebContentsDebuggingEnabled

作用：启用WebView内容的调试功能（主要用于开发环境）。

## 2.Process APIs
与Android系统进程相关的方法，用于管理或查询系统进程状态。

android.os.Process.start

作用：启动一个新的进程。
android.os.Process.killProcess

作用：强制终止指定的进程。
android.app.ActivityManager.killBackgroundProcesses

作用：终止指定包名的后台进程。

## 3.Command APIs
与命令执行相关的方法，通常用于运行系统命令。

java.lang.Runtime.exec

作用：运行系统命令或启动新进程。
java.lang.ProcessBuilder.start

作用：使用ProcessBuilder构建并启动新进程。

## 4.File IO APIs
文件读写相关的操作方法，用于文件操作。

libcore.io.IoBridge.open

作用：打开文件或套接字，用于I/O操作。
android.content.ContextWrapper.openFileInput

作用：打开一个应用私有的文件进行读取。
android.content.ContextWrapper.openFileOutput

作用：打开一个应用私有的文件进行写入。
android.content.ContextWrapper.deleteFile

作用：删除应用私有目录中的指定文件。

## 5.Database APIs
与SQLite数据库相关的方法，用于操作应用程序的本地数据库。

android.content.ContextWrapper.openOrCreateDatabase

作用：打开或创建一个数据库文件。
android.database.sqlite.SQLiteDatabase.execSQL

作用：执行SQL命令（如创建表或插入数据）。
android.database.sqlite.SQLiteDatabase.query

作用：查询数据库中的表，并返回Cursor对象。
android.database.sqlite.SQLiteDatabase.insert

作用：插入一条记录到数据库表中。
android.database.sqlite.SQLiteDatabase.update

作用：更新数据库表中的记录。

## 6.Crypto APIs
加密相关的API，用于处理加密或哈希操作。

javax.crypto.spec.SecretKeySpec.$init

作用：初始化一个密钥对象，用于加密操作。
javax.crypto.Cipher.doFinal

作用：执行加密或解密操作。
java.security.MessageDigest.digest

作用：生成消息摘要（哈希值）。
java.security.MessageDigest.update

作用：更新消息摘要的输入数据。

## 7.Device Info APIs
设备信息查询相关的方法，用于获取设备标识符、网络状态等信息。

android.telephony.TelephonyManager.getDeviceId

作用：获取设备的唯一标识符（已废弃，建议使用更安全的标识符）。
android.net.wifi.WifiInfo.getMacAddress

作用：获取设备的MAC地址。
android.telephony.TelephonyManager.getSimCountryIso

作用：获取SIM卡的国家ISO代码。
android.content.pm.PackageManager.getInstalledPackages

作用：获取设备上安装的应用包信息。

## 8.Network APIs
网络通信相关的API，用于发起HTTP请求或打开网络连接。

java.net.URL.openConnection

作用：打开一个到指定URL的连接。
org.apache.http.impl.client.AbstractHttpClient.execute

作用：执行HTTP请求。

## 9.System Manager APIs
系统管理相关的方法，用于管理系统组件状态。

android.app.ApplicationPackageManager.setComponentEnabledSetting

作用：启用或禁用应用程序的组件。
android.telephony.TelephonyManager.listen

作用：监听设备的电话状态或网络状态变化。

## 10.SMS APIs
短信功能相关的API，用于发送或管理短信。

android.telephony.SmsManager.sendTextMessage

作用：发送一条文本短信。
android.telephony.SmsManager.sendMultipartTextMessage

作用：发送一条分段短信。

## 11.Device Data APIs
设备数据操作相关的方法，用于读取或修改设备存储的数据。

android.content.ContentResolver.query

作用：查询内容提供者中的数据。
android.content.ContentResolver.insert

作用：向内容提供者插入数据。
android.content.ContentResolver.delete

作用：从内容提供者中删除数据。