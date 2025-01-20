C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe -s emulator-5554 kill-server
C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe -s emulator-5554 start-server
C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe devices -l
C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe -s emulator-5554 shell echo "[OK]:Connect to AVD, Ready for root."
C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe devices -l
C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe -s emulator-5554 root
C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe devices -l
C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe -s emulator-5554 remount