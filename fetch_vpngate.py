import requests
import csv
import os

url = "https://www.vpngate.net/api/iphone"
response = requests.get(url)
data = response.text.splitlines()

# 新数据保存在内存中
new_data = [line.split(',') for line in data]

# 检查旧文件是否存在
if os.path.exists('servers.csv'):
    with open('servers.csv', 'r') as csvfile:
        old_data = list(csv.reader(csvfile))
    # 如果数据相同，则直接退出
    if old_data == new_data:
        print("No changes detected in servers.csv.")
        exit(0)

# 写入新数据
with open('servers.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerows(new_data)

print("servers.csv updated successfully.")