import os
import sys
import time
import json
import shutil
import logging
import requests
import subprocess
import collections
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
from quick_static_analyzer import QuickStaticAnalyzer

class DynamicAnalyzer:
    def __init__(self, mobsf_root: str = 'F:/MobSFCODE/Mobile-Security-Framework-MobSF-master/mobsf',
                 android_version: str = None, output_directory: str = None):
        self.api_key = "SeeWhatYouHaveRatherWhatYouDoNotHave"
        self.headers = {"Authorization": self.api_key}
        self.server = "http://localhost:8000"
        self.mobsf_root = Path(mobsf_root)
        self.android_version = android_version
        self.output_directory = Path(output_directory) if output_directory else None
        self.results_file = self.mobsf_root / 'analysis_results.json'
        self.setup_logging()

    def parse_api_logs(self, input_file: str, output_file: str) -> Dict:
        """解析API日志并计数"""
        api_counter = collections.defaultdict(lambda: {'count': 0, 'name': ''})
        
        with open(input_file, 'r') as f:
            content = f.read()
            log_entries = content.split('},{')
            
            for entry in log_entries:
                try:
                    if not entry.startswith('{'):
                        entry = '{' + entry
                    if not entry.endswith('}'):
                        entry = entry + '}'
                        
                    log_entry = json.loads(entry)
                    api_key = f"{log_entry['class']}.{log_entry['method']}"
                    api_counter[api_key]['count'] += 1
                    api_counter[api_key]['name'] = log_entry['name']
                except (json.JSONDecodeError, KeyError):
                    continue

        with open(output_file, 'w') as f:
            f.write("API名称,API接口,调用次数\n")
            sorted_apis = sorted(api_counter.items(), key=lambda x: x[1]['count'], reverse=True)
            for api, info in sorted_apis:
                f.write(f"{info['name']},{api},{info['count']}\n")

        return api_counter
        
    def setup_logging(self):
        """设置日志记录"""
        if not self.output_directory:
            raise ValueError("Output directory is required for logging")
            
        self.output_directory.mkdir(exist_ok=True, parents=True)
        log_file = self.output_directory / 'dynamic_analysis.log'
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Set up file handler
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setFormatter(formatter)
        
        # Set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Set up logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Remove any existing handlers
        self.logger.handlers.clear()
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Prevent propagation to root logger
        self.logger.propagate = False

    def load_previous_results(self) -> List[Dict]:
        """加载之前的分析结果"""
        if self.results_file.exists():
            with open(self.results_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []

    def save_result(self, result: Dict):
        """保存分析结果"""
        results = self.load_previous_results()
        result['android_version'] = self.android_version
        results.append(result)
        with open(self.results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

    def is_app_analyzed(self, apk_path: str, md5_hash: str) -> bool:
        """检查应用是否已被分析"""
        results = self.load_previous_results()
        return any(
            r['apk_path'] == str(apk_path) and
            r['hash'] == md5_hash and
            r['android_version'] == self.android_version
            for r in results
        )

    def find_apps(self, directory: str) -> List[str]:
        """查找目录中的APK和XAPK文件"""
        directory = Path(directory)
        apps = []
        for ext in ['.apk', '.xapk']:
            apps.extend(str(p) for p in directory.glob(f'*{ext}'))
        return sorted(apps)

    def analyze_all_apps(self, apps_directory: str):
        """分析目录中的所有应用"""
        apps = self.find_apps(apps_directory)
        total_apps = len(apps)
        self.logger.info(f"Found {total_apps} apps in {apps_directory}")
        
        for index, app_path in enumerate(apps, 1):
            self.logger.info(f"Processing app {index}/{total_apps}: {app_path}")
            result = self.run_dynamic_analysis(app_path, test_duration=45)
            if result['success']:
                self.logger.info(f"Successfully analyzed app {index}/{total_apps}")
            else:
                self.logger.error(f"Failed to analyze app {index}/{total_apps} at step {result['step']}: {result['error']}")


    def run_dynamic_analysis(self, apk_path: str, test_duration: int = 300, 
                           monkey_seed: int = 42, event_delay: int = 5) -> Dict[str, Any]:
        """执行动态分析流程"""
        start_time = time.time()
        readable_start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
        result = {
            'start_time': readable_start_time,
            'success': False,
            'apk_path': str(apk_path),
            'hash': None,
            'package_name': None,
            'test_duration': test_duration,
            'monkey_seed': monkey_seed,
            'error': None,
            'android_version': self.android_version,
            'step': 0  # Added step tracking
        }
        
        try:
            # Step 1: Static Analysis
            self.logger.info("(1/6) Starting static analysis")
            static_analyzer = QuickStaticAnalyzer()
            md5_hash = self._static_analysis(static_analyzer, apk_path)
            if not md5_hash:
                result['step'] = 1
                raise Exception("Static analysis failed")
            result['hash'] = md5_hash
            
            if self.is_app_analyzed(apk_path, md5_hash):
                self.logger.info(f"App already analyzed for Android version {self.android_version}")
                return result

            # Step 2: Start Dynamic Analysis
            self.logger.info("(2/6) Starting dynamic analysis")
            if not self._start_dynamic_analysis(static_analyzer, md5_hash):
                result['step'] = 2
                raise Exception("Failed to start dynamic analysis")

            # Get package name
            from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
            latest_record = StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).last()
            if latest_record:
                result['package_name'] = latest_record.PACKAGE_NAME
            else:
                result['step'] = 2
                raise Exception("Could not find package name in database")

            # Step 3: Frida Instrumentation
            self.logger.info("(3/6) Starting Frida instrumentation")
            if not self._start_frida_instrumentation(md5_hash):
                result['step'] = 3
                raise Exception("Frida instrumentation failed")

            # Step 4: Monkey Test
            self.logger.info("(4/6) Running Monkey test")
            if not self._run_monkey_test(result['package_name'], md5_hash, 
                                       duration=test_duration, seed=monkey_seed, 
                                       throttle=event_delay):
                result['step'] = 4
                raise Exception("Monkey test failed")

            # Step 5: Stop Analysis
            self.logger.info("(5/6) Stopping dynamic analysis")
            if not self._stop_dynamic_analysis(md5_hash):
                result['step'] = 5
                raise Exception("Failed to stop dynamic analysis")

            # Step 6: Organize Files
            self.logger.info("(6/6) Organizing output files")
            self._organize_output_files(md5_hash)
            
            result['success'] = True
            
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Error during dynamic analysis at step {result['step']}: {error_msg}")
            result['error'] = error_msg
        finally:
            result['total_time'] = time.time() - start_time
            self._log_analysis_result(result)
            self.save_result(result)
            if result['hash']:
                self._organize_output_files(result['hash'])
        return result

    def _static_analysis(self, static_analyzer: QuickStaticAnalyzer, apk_path: str) -> Optional[str]:
        """执行静态分析"""
        return static_analyzer.quick_save_for_dynamic(apk_path)

    def _start_dynamic_analysis(self, static_analyzer: QuickStaticAnalyzer, md5_hash: str) -> bool:
        """启动动态分析"""
        return static_analyzer.start_dynamic_analysis(md5_hash)

    def _log_analysis_result(self, result: Dict[str, Any]) -> None:
        """记录分析结果"""
        log_message = f"""
        Analysis Results:
        ----------------
        Success: {result['success']}
        APK Path: {result['apk_path']}
        Hash: {result['hash']}
        Package Name: {result['package_name']}
        Android Version: {result['android_version']}
        Test Duration: {result['test_duration']} seconds
        Monkey Seed: {result['monkey_seed']}
        Total Time: {result.get('total_time', 'N/A')} seconds
        Error: {result.get('error', 'None')}
        """
        self.logger.info(log_message)
        
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
        
        # 检查是否生成了API监控日志
        api_monitor_file = output_dir / 'mobsf_api_monitor.txt'
        if api_monitor_file.exists():
            # 生成API计数结果
            output_csv = output_dir / 'api_count_result.csv'
            self.parse_api_logs(str(api_monitor_file), str(output_csv))
            required_files.append('api_count_result.csv')
        
            # 复制文件到目标目录
            target_dir = self.output_directory / md5_hash
            target_dir.mkdir(exist_ok=True, parents=True)
            
            for file_name in required_files:
                src = output_dir / file_name
                if src.exists():
                    shutil.copy2(src, target_dir / file_name)
        
        # 创建临时目录保存所需文件
        temp_dir = output_dir / 'temp'
        temp_dir.mkdir(exist_ok=True)
        
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
                
        shutil.rmtree(temp_dir)

def main():
    if len(sys.argv) != 4:
        print("Usage: python dynamic_analyzer.py <android_version> <apps_directory> <output_directory>")
        sys.exit(1)
        
    android_version = sys.argv[1]
    apps_directory = sys.argv[2]
    output_directory = sys.argv[3]
    
    if not os.path.exists(apps_directory):
        print("Apps directory not found!")
        sys.exit(1)
        
    analyzer = DynamicAnalyzer(android_version=android_version, output_directory=output_directory)
    analyzer.analyze_all_apps(apps_directory)

if __name__ == "__main__":
    main()