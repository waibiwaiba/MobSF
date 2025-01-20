import sys
import subprocess
import time
import logging
import requests
import json
import os

class MobSFAutomation:
    def __init__(self, avd_id, app_path):
        self.avd_id = avd_id
        self.app_path = app_path
        self.mobsf_url = "http://localhost:8000"
        self.api_key = "SeeWhatYouHaveRatherWhatYouDoNotHave"
        self.headers = {"Authorization": self.api_key}
        
    def run_command(self, command, ignore_errors=False):
        """运行命令行命令"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            if ignore_errors:
                return e.stdout
            else:
                logging.error(f"Command '{' '.join(command)}' failed with error: {e.stderr}")
                sys.exit(1)

    def wait_for_boot(self):
        """等待模拟器完全启动"""
        logging.info("Waiting for emulator to fully boot...")
        for _ in range(60):
            bootanim = self.run_command(["adb", "-s", "emulator-5554", "shell", "getprop", "init.svc.bootanim"], ignore_errors=True)
            if "stopped" in bootanim:
                boot_completed = self.run_command(["adb", "-s", "emulator-5554", "shell", "getprop", "sys.boot_completed"], ignore_errors=True)
                if boot_completed.strip() == "1":
                    logging.info("Emulator boot completed.")
                    return True
            time.sleep(5)
        logging.error("Emulator failed to fully boot within the timeout period.")
        return False

    def start_avd(self):
        """启动AVD"""
        logging.info(f"Starting AVD: {self.avd_id}")
        start_avd_script = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\scripts\start_avd.ps1"
        self.run_command(["powershell", "-File", start_avd_script, self.avd_id])
        if self.wait_for_boot():
            logging.info(f"AVD {self.avd_id} started successfully.")
        else:
            logging.error(f"Failed to start AVD {self.avd_id}.")
            sys.exit(1)

    def start_mobsf(self):
        """启动MobSF服务器"""
        logging.info("Starting MobSF server...")
        mobsf_script = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\run.bat"
        try:
            subprocess.Popen([mobsf_script], shell=True)
            time.sleep(10)  # 给MobSF更多启动时间
        except Exception as e:
            logging.error(f"Failed to start MobSF server: {e}")
            sys.exit(1)

    def upload_apk(self):
        """上传APK文件到MobSF"""
        logging.info(f"Uploading APK: {self.app_path}")
        with open(self.app_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(
                f"{self.mobsf_url}/api/v1/upload",
                files=files,
                headers=self.headers
            )
            if response.status_code == 200:
                result = response.json()
                return result.get('hash')
            else:
                logging.error(f"Failed to upload APK: {response.text}")
                return None

    def start_dynamic_analysis(self, file_hash):
        """开始动态分析"""
        logging.info("Starting dynamic analysis...")
        response = requests.post(
            f"{self.mobsf_url}/api/v1/dynamic/start_analysis",
            data={"hash": file_hash},
            headers=self.headers
        )
        return response.status_code == 200

    def stop_dynamic_analysis(self, file_hash):
        """停止动态分析"""
        logging.info("Stopping dynamic analysis...")
        response = requests.post(
            f"{self.mobsf_url}/api/v1/dynamic/stop_analysis",
            data={"hash": file_hash},
            headers=self.headers
        )
        return response.status_code == 200

    def collect_logs(self, file_hash):
        """收集分析日志"""
        # 这个函数将在后续完善，用于收集和整理api_monitor、frida、logcat日志
        pass

    def run(self):
        """运行完整的分析流程"""
        # 1. 启动环境
        self.start_avd()
        self.start_mobsf()
        
        # 2. 上传并分析APK
        file_hash = self.upload_apk()
        if not file_hash:
            logging.error("Failed to upload APK")
            return
        
        # 3. 进行动态分析
        if self.start_dynamic_analysis(file_hash):
            # TODO: 等待一定时间或特定条件
            time.sleep(300)  # 示例：等待5分钟
            
            # 4. 停止分析
            if self.stop_dynamic_analysis(file_hash):
                # 5. 收集日志
                self.collect_logs(file_hash)
            else:
                logging.error("Failed to stop dynamic analysis")
        else:
            logging.error("Failed to start dynamic analysis")

def main():
    if len(sys.argv) != 3:
        logging.error("Usage: python script.py AVD app\\absolute\\path")
        sys.exit(1)

    avd_id = sys.argv[1]
    app_path = sys.argv[2]

    automation = MobSFAutomation(avd_id, app_path)
    automation.run()

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    main()