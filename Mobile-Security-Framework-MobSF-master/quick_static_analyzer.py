import os
import sys
import json
import django
import hashlib
import logging
import zipfile
import shutil
import requests
from pathlib import Path
import tempfile

# 设置Django环境
sys.path.append('F:/MobSFCODE/Mobile-Security-Framework-MobSF-master/mobsf')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mobsf.MobSF.settings")
django.setup()

from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid, RecentScansDB
from mobsf.MobSF.utils import get_md5

class QuickStaticAnalyzer:
    def __init__(self):
        self.api_key = "SeeWhatYouHaveRatherWhatYouDoNotHave"
        self.headers = {"Authorization": self.api_key}
        self.server = "http://localhost:8000"
        
    def get_package_name(self, apk_path):
        """使用aapt获取包名"""
        try:
            import subprocess
            cmd = ['aapt', 'dump', 'badging', apk_path]
            output = subprocess.check_output(cmd).decode('utf-8', errors='ignore')
            
            # 在输出中查找包名
            for line in output.split('\n'):
                if line.startswith('package:'):
                    items = line.split(' ')
                    for item in items:
                        if item.startswith('name='):
                            return item.split('=')[1].strip("'")
            return None
        except Exception as e:
            logging.error(f"Error getting package name: {str(e)}")
            return None

    def extract_xapk(self, xapk_path):
        """从XAPK中提取主APK文件"""
        try:
            # 创建临时目录
            temp_dir = tempfile.mkdtemp()
            logging.info(f"Extracting XAPK to {temp_dir}")

            # 解压XAPK
            with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            # 读取manifest.json
            manifest_path = os.path.join(temp_dir, 'manifest.json')
            if not os.path.exists(manifest_path):
                raise Exception("manifest.json not found in XAPK")

            with open(manifest_path) as f:
                manifest = json.load(f)

            # 获取主APK文件名
            main_apk = None
            if 'split_apks' in manifest:  # 新格式
                for apk in manifest['split_apks']:
                    if apk.get('id') == 'base':
                        main_apk = apk.get('file')
                        break
            else:  # 旧格式
                main_apk = manifest.get('package_name') + '.apk'

            if not main_apk or not os.path.exists(os.path.join(temp_dir, main_apk)):
                # 尝试查找任何.apk文件
                apk_files = [f for f in os.listdir(temp_dir) if f.endswith('.apk')]
                if apk_files:
                    main_apk = apk_files[0]
                else:
                    raise Exception("No APK file found in XAPK")

            # 复制主APK到临时文件
            temp_apk = os.path.join(temp_dir, "temp_main.apk")
            shutil.copy2(os.path.join(temp_dir, main_apk), temp_apk)
            
            return temp_apk, temp_dir
            
        except Exception as e:
            logging.error(f"Error extracting XAPK: {str(e)}")
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            return None, None

    def quick_save_for_dynamic(self, file_path):
        """保存必要的数据到数据库"""
        temp_dir = None
        try:
            original_file_name = os.path.basename(file_path)
            is_xapk = original_file_name.endswith('.xapk')
            
            if is_xapk:
                # 处理XAPK
                apk_path, temp_dir = self.extract_xapk(file_path)
                if not apk_path:
                    return None
            else:
                apk_path = file_path

            # 计算MD5（使用原始文件的MD5）
            md5 = get_md5(file_path)
            
            # 获取包名（从提取的APK中获取）
            package_name = self.get_package_name(apk_path)
            if not package_name:
                logging.error("Could not get package name")
                return None
                
            logging.info(f"Processing {original_file_name} ({package_name})")
            
            # 创建uploads目录下的文件夹和复制文件
            upload_dir = Path('F:/MobSFCODE/Mobile-Security-Framework-MobSF-master/mobsf/uploads') / md5
            os.makedirs(upload_dir, exist_ok=True)
            target_path = upload_dir / f"{md5}.{original_file_name.split('.')[-1]}"  # 保持原始扩展名
            
            if not os.path.exists(target_path):
                shutil.copy2(file_path, target_path)
            
            # 保存到数据库
            # StaticAnalyzerAndroid
            static_entry = StaticAnalyzerAndroid(
                FILE_NAME=original_file_name,
                APP_TYPE='apk' if not is_xapk else 'xapk',
                MD5=md5,
                PACKAGE_NAME=package_name,
                APP_NAME=original_file_name,  # 使用文件名作为应用名
            )
            static_entry.save()
            
            # RecentScansDB
            recent_entry = RecentScansDB(
                FILE_NAME=original_file_name,
                MD5=md5,
                APP_NAME=original_file_name,
                PACKAGE_NAME=package_name,
                ANALYZER='static_analyzer',
                SCAN_TYPE='apk' if not is_xapk else 'xapk',
            )
            recent_entry.save()
            
            logging.info(f"Successfully saved {original_file_name} to database")
            return md5
            
        except Exception as e:
            logging.error(f"Error in quick_save_for_dynamic: {str(e)}")
            return None
        finally:
            # 清理临时目录
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    def start_dynamic_analysis(self, md5):
        """启动动态分析"""
        try:
            url = f"{self.server}/api/v1/dynamic/start_analysis"
            data = {"hash": md5}
            response = requests.post(url, data=data, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logging.error(f"Error starting dynamic analysis: {str(e)}")
            return None

def main():
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) != 2:
        print("Usage: python quick_static_analyzer.py <file_path>")
        print("Supported formats: .apk, .xapk")
        sys.exit(1)
        
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print("File not found!")
        sys.exit(1)
        
    if not file_path.endswith(('.apk', '.xapk')):
        print("Unsupported file format. Only .apk and .xapk files are supported.")
        sys.exit(1)
        
    analyzer = QuickStaticAnalyzer()
    md5 = analyzer.quick_save_for_dynamic(file_path)
    
    if md5:
        print(f"Successfully processed file. MD5: {md5}")
        result = analyzer.start_dynamic_analysis(md5)
        if result:
            print("Dynamic analysis started successfully")
        else:
            print("Failed to start dynamic analysis")
    else:
        print("Failed to process file")

if __name__ == "__main__":
    main()