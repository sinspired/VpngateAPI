import urllib.request
import csv

url = "https://www.vpngate.net/api/iphone"

# 发送 GET 请求
response = urllib.request.urlopen(url)
data = response.read().decode('utf-8').text.splitlines()

with open('servers.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    for line in data:
        csvwriter.writerow(line.split(','))