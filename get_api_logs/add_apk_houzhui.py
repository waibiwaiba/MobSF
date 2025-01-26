import os

# 定义目标目录
target_dir = r"F:\Downloads\Adware.tar\Adware"

# 确保目录存在
if not os.path.exists(target_dir):
    print(f"目录 {target_dir} 不存在！请检查路径。")
else:
    # 遍历目录中的所有文件
    for filename in os.listdir(target_dir):
        # 拼接完整的文件路径
        file_path = os.path.join(target_dir, filename)

        # 检查是否是文件（忽略子目录）
        if os.path.isfile(file_path):
            # 如果文件已经有 .apk 后缀，则跳过
            if not filename.endswith(".apk"):
                # 新的文件名
                new_filename = filename + ".apk"
                new_file_path = os.path.join(target_dir, new_filename)

                # 重命名文件
                os.rename(file_path, new_file_path)
                print(f"已重命名: {filename} -> {new_filename}")
            else:
                print(f"文件已带有 .apk 后缀，跳过: {filename}")
    print("文件重命名完成！")
