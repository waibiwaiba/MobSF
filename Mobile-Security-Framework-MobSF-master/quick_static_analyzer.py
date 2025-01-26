import os
import sys
import json
import django
import hashlib
import logging
import zipfile
import shutil
import requests
import logging
from pathlib import Path
from json import load


logger = logging.getLogger(__name__)

# 设置Django环境
sys.path.append('F:/MobSFCODE/Mobile-Security-Framework-MobSF-master/mobsf')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mobsf.MobSF.settings")
django.setup()

from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid, RecentScansDB
from mobsf.MobSF.utils import get_md5_of_file, is_file_exists

class QuickStaticAnalyzer:
    def __init__(self):
        self.api_key = "SeeWhatYouHaveRatherWhatYouDoNotHave"
        self.headers = {"Authorization": self.api_key}
        self.server = "http://localhost:8000"
        self.mobsf_root = Path('F:/MobSFCODE/Mobile-Security-Framework-MobSF-master/mobsf')
        
    def handle_xapk(self, app_dic):
        """基于MobSF的XAPK处理方法"""
        data = None
        checksum = app_dic['md5']
        xapk = Path(app_dic['app_dir']) / f'{checksum}.xapk'
        apk = Path(app_dic['app_dir']) / f'{checksum}.apk'
        
        # 解压XAPK
        with zipfile.ZipFile(xapk, 'r') as zf:
            files = zf.namelist()
            if 'manifest.json' not in files:
                logger.error('Manifest file not found in XAPK')
                return False
            # 提取manifest.json
            zf.extract('manifest.json', app_dic['app_dir'])
            
        # 读取manifest
        manifest_path = Path(app_dic['app_dir']) / 'manifest.json'
        with open(manifest_path, encoding='utf8', errors='ignore') as f:
            data = load(f)
            
        if not data:
            logger.error('Manifest file is empty')
            return False
            
        apks = data.get('split_apks')
        if not apks:
            logger.error('Split APKs not found')
            return False
            
        # 提取base APK
        with zipfile.ZipFile(xapk, 'r') as zf:
            for a in apks:
                if a['id'] == 'base':
                    base_apk = a['file']
                    zf.extract(base_apk, app_dic['app_dir'])
                    base_apk_path = Path(app_dic['app_dir']) / base_apk
                    if base_apk_path.exists():
                        shutil.move(base_apk_path, apk)
                        return True
                        
        return False

    def get_package_name(self, apk_path):
        """使用AndroidManifest.xml获取包名"""
        try:
            import subprocess
            from xml.dom import minidom

            # 使用aapt获取AndroidManifest.xml
            cmd = ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml']
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            
            # 解析输出，查找package属性
            for line in output.split('\n'):
                if 'package=' in line:
                    # 使用正则表达式或字符串处理提取包名
                    package = line.split('package="')[1].split('"')[0]
                    return package
                    
            return None
        except Exception as e:
            logging.error(f"Error getting package name: {str(e)}")
            return None

    def quick_save_for_dynamic(self, file_path):
        """保存必要的数据到数据库"""
        try:
            original_file_name = os.path.basename(file_path)
            is_xapk = original_file_name.endswith('.xapk')
            md5 = get_md5_of_file(file_path)
            
            # 准备上传目录结构
            uploads_dir = self.mobsf_root / 'uploads'
            app_dir = uploads_dir / md5
            os.makedirs(app_dir, exist_ok=True)
            
            # 复制文件到上传目录
            if is_xapk:
                target_path = app_dir / f"{md5}.xapk"
                shutil.copy2(file_path, target_path)
                
                # 处理XAPK
                app_dic = {
                    'md5': md5,
                    'app_dir': app_dir,
                }
                if not self.handle_xapk(app_dic):
                    logging.error("Failed to handle XAPK")
                    return None
                
                # 从提取的APK获取包名
                apk_path = app_dir / f"{md5}.apk"
            else:
                # 普通APK处理
                target_path = app_dir / f"{md5}.apk"
                shutil.copy2(file_path, target_path)
                apk_path = target_path
                
            package_name = self.get_package_name(apk_path)
            if not package_name:
                logging.error("Could not get package name")
                return None
                
            logging.info(f"Processing {original_file_name} ({package_name})")
            
            # 保存到数据库
            # StaticAnalyzerAndroid
            static_entry = StaticAnalyzerAndroid(
                FILE_NAME=original_file_name,
                APP_TYPE='xapk' if is_xapk else 'apk',
                MD5=md5,
                PACKAGE_NAME=package_name,
                APP_NAME=original_file_name,
            )
            static_entry.save()
            
            # RecentScansDB
            recent_entry = RecentScansDB(
                FILE_NAME=original_file_name,
                MD5=md5,
                APP_NAME=original_file_name,
                PACKAGE_NAME=package_name,
                ANALYZER='static_analyzer',
                SCAN_TYPE='xapk' if is_xapk else 'apk',
            )
            recent_entry.save()
            
            logging.info(f"Successfully saved {original_file_name} to database")
            return md5
            
        except Exception as e:
            logging.error(f"Error in quick_save_for_dynamic: {str(e)}")
            return None

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