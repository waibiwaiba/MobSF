import csv

# 读取 API-SET.csv 并生成初步的 API 列表
def generate_api_list(csv_file, output_csv_file):
    api_list = []
    with open(csv_file, "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        
        # 提取 Union 列中的 API 数据
        for i, row in enumerate(reader):
            api = row.get("Union", "").strip()
            if api:
                # 分割为 class 和 method
                parts = api.split(" ")
                if len(parts) == 2:
                    classname, methodname = parts
                    
                    # 构造 API 字典
                    api_entry = {
                        "id": i + 3,  # 编号从 1 开始
                        "class": classname,
                        "method": methodname,
                        "name": "",  # 初始为空或默认值
                        "enabled": True,  # 默认开启监听
                        "description": ""  # 初始为空
                    }
                    api_list.append(api_entry)

    # 保存为 CSV 文件
    fieldnames = ["id", "class", "method", "name", "enabled", "description"]
    with open(output_csv_file, "w", newline="", encoding="utf-8") as output_csv:
        writer = csv.DictWriter(output_csv, fieldnames=fieldnames)
        writer.writeheader()  # 写入表头
        writer.writerows(api_list)  # 写入数据

    print(f"API list has been saved to {output_csv_file}")


# 示例使用
csv_file = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\mobsf\DynamicAnalyzer\tools\frida_scripts\android\default\API Set.csv"  # 输入的 API-SET.csv 文件路径
output_csv_file = r"F:\MobSFCODE\Mobile-Security-Framework-MobSF-master\mobsf\DynamicAnalyzer\tools\frida_scripts\android\default\hooked_api_list.csv"  # 生成的 API 列表 CSV 文件路径
generate_api_list(csv_file, output_csv_file)
