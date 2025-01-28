import json
import collections
from pathlib import Path

def parse_api_logs(input_file, output_file):
   # 计数器存储api调用信息
   api_counter = collections.defaultdict(lambda: {'count': 0, 'name': ''})
   
   # 读取单行日志内容
   with open(input_file, 'r', encoding='utf-8') as f:
       content = f.read()
       # 分割每条日志记录
       log_entries = content.split('},{')
       
       for entry in log_entries:
           try:
               # 处理首尾的花括号
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

   # 按调用次数降序排序并写入
   with open(output_file, 'w', encoding='utf-8') as f:
       f.write("API名称,API接口,调用次数\n")
       sorted_apis = sorted(api_counter.items(), key=lambda x: x[1]['count'], reverse=True)
       for api, info in sorted_apis:
           f.write(f"{info['name']},{api},{info['count']}\n")

   return api_counter

if __name__ == "__main__":
   input_file = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\mobsf\uploads\8b85d468603bbe35cd5ad50d3ca14081\mobsf_api_monitor.txt"
   output_file = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\mobsf\uploads\8b85d468603bbe35cd5ad50d3ca14081\api_statistics.csv"
   results = parse_api_logs(input_file, output_file)