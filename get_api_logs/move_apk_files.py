import os
import shutil
from pathlib import Path

def move_apk_files_in_batches(source_dir, batch_size=50):
    # 将源目录转换为 Path 对象
    source_dir = Path(source_dir)
    
    # 获取所有 .apk 文件
    apk_files = list(source_dir.glob("*.apk"))
    total_files = len(apk_files)
    
    # 如果没有 .apk 文件，直接退出
    if total_files == 0:
        print("No .apk files found in the directory.")
        return
    
    # 计算需要多少个子目录
    num_batches = (total_files // batch_size) + (1 if total_files % batch_size != 0 else 0)
    
    # 创建子目录并移动文件
    for batch_num in range(1, num_batches + 1):
        # 创建子目录名称（如 01, 02, ...）
        subdir_name = f"{batch_num:02d}"
        subdir_path = source_dir / subdir_name
        
        # 创建子目录
        subdir_path.mkdir(exist_ok=True)
        
        # 计算当前批次的文件范围
        start_index = (batch_num - 1) * batch_size
        end_index = start_index + batch_size
        
        # 获取当前批次的文件
        batch_files = apk_files[start_index:end_index]
        
        # 移动文件到子目录
        for apk_file in batch_files:
            shutil.move(str(apk_file), str(subdir_path / apk_file.name))
        
        print(f"Moved {len(batch_files)} files to {subdir_path}")

    print(f"All files have been moved into {num_batches} subdirectories.")

# 调用函数
# source_directory = r"F:\Downloads\Adware.tar\Adware"
# source_directory = r"F:\Downloads\Banking.tar\Banking"
# source_directory = r"F:\Downloads\Riskware.tar\Riskware"
source_directory = r"F:\Downloads\SMS2.tar\SMS2\SMS"

move_apk_files_in_batches(source_directory)