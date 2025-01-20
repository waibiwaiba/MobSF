import sys
import subprocess
import time
import logging

def run_command(command, ignore_errors=False):
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

def wait_for_boot():
    """等待模拟器完全启动"""
    logging.info("Waiting for emulator to fully boot...")
    for _ in range(60):
        bootanim = run_command(["adb", "-s", "emulator-5554", "shell", "getprop", "init.svc.bootanim"], ignore_errors=True)
        if "stopped" in bootanim:
            boot_completed = run_command(["adb", "-s", "emulator-5554", "shell", "getprop", "sys.boot_completed"], ignore_errors=True)
            if boot_completed.strip() == "1":
                logging.info("Emulator boot completed.")
                return True
        time.sleep(5)
    logging.error("Emulator failed to fully boot within the timeout period.")
    return False

def start_avd(avd_id):
    """启动AVD"""
    logging.info(f"Starting AVD: {avd_id}")
    start_avd_script = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\scripts\start_avd.ps1"
    run_command(["powershell", "-File", start_avd_script, avd_id])
    if wait_for_boot():
        logging.info(f"AVD {avd_id} started successfully.")
    else:
        logging.error(f"Failed to start AVD {avd_id}.")
        sys.exit(1)

def start_mobsf():
    """启动MobSF服务器"""
    logging.info("Starting MobSF server...")
    mobsf_script = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\run.bat"
    try:
        subprocess.Popen([mobsf_script], shell=True)
        time.sleep(5)  # 等待MobSF服务器启动
    except Exception as e:
        logging.error(f"Failed to start MobSF server: {e}")
        logging.info("Continuing script execution despite the error.")


def main():
    if len(sys.argv) != 3:
        logging.error("Usage: python script.py AVD app\\absolute\\path")
        sys.exit(1)

    avd_id = sys.argv[1]
    app_path = sys.argv[2]

    start_avd(avd_id)
    start_mobsf()

    # 其他步骤将在后续实现
    logging.info("Script completed.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()