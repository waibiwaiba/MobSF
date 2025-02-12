import os
import json
import datetime
from typing import Dict, Tuple
from collections import defaultdict

def analyze_api_logs(folder_path: str) -> Tuple[str, datetime.datetime, datetime.datetime, float, int, float]:
    """分析指定文件夹中的API日志文件，计算时间差和调用频率
    
    Args:
        folder_path: 包含mobsf_api_monitor.txt的文件夹路径
        
    Returns:
        Tuple包含: 文件夹路径, 首次调用时间, 最后调用时间, 时间差(秒), API总调用数, 每秒平均调用数
    """
    log_file = os.path.join(folder_path, 'mobsf_api_monitor.txt')
    if not os.path.exists(log_file):
        raise FileNotFoundError(f"API日志文件不存在: {log_file}")
        
    with open(log_file, 'r', encoding='utf-8') as f:
        content = f.read()
        log_entries = content.split('},{')
        # 修复最后一个条目的格式
        log_entries[-1] = log_entries[-1].rstrip(',')
        first_time = None
        last_time = None
        total_calls = 0
        
        for i, entry in enumerate(log_entries):
            try:
                if not entry.startswith('{'):
                    entry = '{' + entry
                if not entry.endswith('}'):
                    entry = entry + '}'
                    
                log_entry = json.loads(entry)
                timestamp = datetime.datetime.strptime(log_entry['time'], '%Y-%m-%d %H:%M:%S.%f')
                
                if i == 0:
                    first_time = timestamp
                last_time = timestamp
                total_calls += 1
                    
            except (json.JSONDecodeError, KeyError):
                continue
                
        if not first_time or not last_time:
            raise ValueError("无法从日志中提取时间信息")
            
        time_diff = (last_time - first_time).total_seconds()
        avg_calls_per_second = total_calls / time_diff if time_diff > 0 else 0
        
        return (
            folder_path,
            first_time,
            last_time,
            time_diff,
            total_calls,
            avg_calls_per_second
        )

def main():
    # import sys
    # if len(sys.argv) != 2:
    #     print("用法: python script.py <path1>")
    #     sys.exit(1)
        
    # base_path = sys.argv[1]
    num = "02"
    # base_path = fr"C:\Users\Administrator\Desktop\TODO\api25\adware\{num}"
    # output_file = fr"C:\Users\Administrator\Desktop\TODO\api25\adware\{num}\api_analysis_results.txt"
    
    # base_path = fr"C:\Users\Administrator\Desktop\TODO\api25\banking\{num}"
    # output_file = fr"C:\Users\Administrator\Desktop\TODO\api25\banking\{num}\api_analysis_results.txt"
    
    # base_path = fr"C:\Users\Administrator\Desktop\TODO\api25\riskware\{num}"
    # output_file = fr"C:\Users\Administrator\Desktop\TODO\api25\riskware\{num}\api_analysis_results.txt"
    
    base_path = fr"C:\Users\Administrator\Desktop\TODO\api25\sms\{num}"
    output_file = fr"C:\Users\Administrator\Desktop\TODO\api25\sms\{num}\api_analysis_results.txt"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("文件夹路径,首次调用时间,最后调用时间,时间差(秒),API总调用数,每秒平均调用数\n")
        
        for folder in os.listdir(base_path):
            folder_path = os.path.join(base_path, folder)
            if os.path.isdir(folder_path):
                try:
                    results = analyze_api_logs(folder_path)
                    f.write(f"{results[0]},{results[1]},{results[2]},{results[3]:.2f},{results[4]},{results[5]:.2f}\n")
                    
                    # 打印结果
                    print(f"\n分析结果 - {folder}:")
                    print(f"文件夹路径: {results[0]}")
                    print(f"首次调用时间: {results[1]}")
                    print(f"最后调用时间: {results[2]}")
                    print(f"时间差(秒): {results[3]:.2f}")
                    print(f"API总调用数: {results[4]}")
                    print(f"每秒平均调用数: {results[5]:.2f}")
                    
                except (FileNotFoundError, ValueError) as e:
                    print(f"处理文件夹 {folder_path} 时出错: {str(e)}")

if __name__ == "__main__":
    main()