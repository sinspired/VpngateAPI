import requests
import csv

url = "https://www.vpngate.net/api/iphone"
response = requests.get(url)
data = response.text.splitlines()

with open('servers.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    for line in data:
        csvwriter.writerow(line.split(','))