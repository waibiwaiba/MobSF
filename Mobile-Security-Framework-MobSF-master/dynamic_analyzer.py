import os
import sys
import time
import json
import shutil
import logging
import requests
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
from quick_static_analyzer import QuickStaticAnalyzer

class DynamicAnalyzer:
    def __init__(self, mobsf_root: str = 'F:/MobSFCODE/Mobile-Security-Framework-MobSF-master/mobsf'):
        self.api_key = "SeeWhatYouHaveRatherWhatYouDoNotHave"
        self.headers = {"Authorization": self.api_key}
        self.server = "http://localhost:8000"
        self.mobsf_root = Path(mobsf_root)
        self.setup_logging()
        
    def setup_logging(self):
        """设置日志记录"""
        log_dir = self.mobsf_root / 'logs'
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f'dynamic_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def run_dynamic_analysis(self, apk_path: str, test_duration: int = 300, 
                           monkey_seed: int = 42, event_delay: int = 5) -> Dict[str, Any]:
        """
        执行完整的动态分析流程
        
        Args:
            apk_path: APK文件路径
            test_duration: Monkey测试持续时间（秒）
            monkey_seed: Monkey测试随机种子
            event_delay: 事件之间的延迟（毫秒）
            
        Returns:
            Dict containing analysis results and status
        """
        start_time = time.time()
        result = {
            'success': False,
            'apk_path': str(apk_path),
            'hash': None,
            'package_name': None,
            'test_duration': test_duration,
            'monkey_seed': monkey_seed,
            'error': None
        }
        
        try:
            # 1. 初始化静态分析器
            static_analyzer = QuickStaticAnalyzer()
            
            # 2. 快速静态分析和保存
            self.logger.info(f"Starting static analysis for {apk_path}")
            md5_hash = static_analyzer.quick_save_for_dynamic(apk_path)
            if not md5_hash:
                raise Exception("Static analysis failed")
                
            result['hash'] = md5_hash
            # 获取package_name，从数据库中获取最新的记录
            from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
            latest_record = StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).last()
            if latest_record:
                result['package_name'] = latest_record.PACKAGE_NAME
            else:
                raise Exception("Could not find package name in database")
            
            # 3. 启动动态分析
            self.logger.info(f"Starting dynamic analysis for hash: {md5_hash}")
            dynamic_start = static_analyzer.start_dynamic_analysis(md5_hash)
            if not dynamic_start:
                raise Exception("Failed to start dynamic analysis")
                
            # 4. 启动Frida插桩
            self.logger.info("Starting Frida instrumentation")
            frida_response = self._start_frida_instrumentation(md5_hash)
            if not frida_response:
                raise Exception("Frida instrumentation failed")
                
            # 5. 运行Monkey测试
            self.logger.info("Starting Monkey test")
            monkey_success = self._run_monkey_test(
                result['package_name'],
                md5_hash,
                duration=test_duration,
                seed=monkey_seed,
                throttle=event_delay
            )
            if not monkey_success:
                raise Exception("Monkey test failed")
                
            # 6. 停止动态分析
            self.logger.info("Stopping dynamic analysis")
            stop_response = self._stop_dynamic_analysis(md5_hash)
            if not stop_response:
                raise Exception("Failed to stop dynamic analysis")
                
            # 7. 整理输出文件
            self.logger.info("Organizing output files")
            self._organize_output_files(md5_hash)
            
            result['success'] = True
            
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Error during dynamic analysis: {error_msg}")
            result['error'] = error_msg
        finally:
            result['total_time'] = time.time() - start_time
            self._log_analysis_result(result)
            
        return result

    def _start_frida_instrumentation(self, md5_hash: str) -> bool:
        """启动Frida插桩"""
        try:
            url = f"{self.server}/api/v1/frida/instrument"
            data = {
                "hash": md5_hash,
                "default_hooks": "api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass",
                "auxiliary_hooks": "",
                "frida_code": ""
            }
            response = requests.post(url, data=data, headers=self.headers)
            response.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Frida instrumentation error: {str(e)}")
            return False

    def _run_monkey_test(self, package_name: str, md5_hash: str, duration: int = 300,
                        seed: int = 42, throttle: int = 5) -> bool:
        """
        运行Monkey测试
        
        Args:
            package_name: 应用包名
            md5_hash: 应用的MD5哈希值
            duration: 测试持续时间（秒）
            seed: 随机种子
            throttle: 事件间延迟（毫秒）
        """
        try:
            # 估算事件数量：假设每个事件平均需要throttle毫秒
            events = (duration * 1000) // throttle
            
            command = [
                'adb', 'shell', 'monkey',
                '-p', package_name,
                '--pct-touch', '30',
                '--pct-motion', '20',
                '--pct-appswitch', '20',
                '--pct-majornav', '15',
                '--pct-nav', '15',
                '-s', str(seed),
                '--throttle', str(throttle),
                '--ignore-crashes',
                '--ignore-timeouts',
                '--ignore-security-exceptions',
                '-v', '-v',
                str(events)
            ]
            
            # 运行Monkey并捕获输出
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 设置超时时间（比预期持续时间多给10秒）
            timeout = duration + 10
            
            # 等待进程完成或超时
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                
                # 保存Monkey日志
                log_path = self.mobsf_root / 'uploads' / md5_hash / 'monkey.txt'
                with open(log_path, 'w', encoding='utf-8') as f:
                    f.write(f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")
                
                return process.returncode == 0
                
            except subprocess.TimeoutExpired:
                process.kill()
                self.logger.error("Monkey test timed out")
                return False
                
        except Exception as e:
            self.logger.error(f"Error during Monkey test: {str(e)}")
            return False

    def _stop_dynamic_analysis(self, md5_hash: str) -> bool:
        """停止动态分析"""
        try:
            url = f"{self.server}/api/v1/dynamic/stop_analysis"
            data = {"hash": md5_hash}
            response = requests.post(url, data=data, headers=self.headers)
            response.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Error stopping dynamic analysis: {str(e)}")
            return False

    def _organize_output_files(self, md5_hash: str) -> None:
        """整理输出文件"""
        output_dir = self.mobsf_root / 'uploads' / md5_hash
        required_files = ['logcat.txt', 'mobsf_api_monitor.txt', 
                         'mobsf_frida_out.txt', 'dump.txt', 'monkey.txt']
        
        # 创建临时目录保存所需文件
        temp_dir = output_dir / 'temp'
        temp_dir.mkdir(exist_ok=True)
        
        # 移动所需文件到临时目录
        for file_name in required_files:
            src = output_dir / file_name
            if src.exists():
                shutil.copy2(src, temp_dir / file_name)
            else:
                self.logger.warning(f"Required file not found: {file_name}")
                
        # 清理原目录并移回所需文件
        for item in output_dir.iterdir():
            if item != temp_dir:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
                    
        # 移回所需文件
        for file_name in required_files:
            src = temp_dir / file_name
            if src.exists():
                shutil.move(src, output_dir / file_name)
                
        # 删除临时目录
        shutil.rmtree(temp_dir)

    def _log_analysis_result(self, result: Dict[str, Any]) -> None:
        """记录分析结果"""
        log_message = f"""
        Analysis Results:
        ----------------
        Success: {result['success']}
        APK Path: {result['apk_path']}
        Hash: {result['hash']}
        Package Name: {result['package_name']}
        Test Duration: {result['test_duration']} seconds
        Monkey Seed: {result['monkey_seed']}
        Total Time: {result.get('total_time', 'N/A')} seconds
        Error: {result.get('error', 'None')}
        """
        self.logger.info(log_message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python dynamic_analyzer.py <apk_path>")
        sys.exit(1)
        
    apk_path = sys.argv[1]
    if not os.path.exists(apk_path):
        print("APK file not found!")
        sys.exit(1)
        
    analyzer = DynamicAnalyzer()
    result = analyzer.run_dynamic_analysis(
        apk_path,
        test_duration=60,  # 5分钟测试时间
        monkey_seed=42,     # 固定随机种子
        event_delay=5     # 5毫秒事件延迟
    )
    
    if result['success']:
        print("Dynamic analysis completed successfully!")
    else:
        print(f"Dynamic analysis failed: {result['error']}")

if __name__ == "__main__":
    main()