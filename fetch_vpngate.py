import urllib.request
import csv

url = "https://www.vpngate.net/api/iphone"

# Send GET request
with urllib.request.urlopen(url) as response:
    # Decode the response content (urllib returns bytes)
    data = response.read().decode('utf-8')  # Decode bytes to a string

# Split lines from the decoded string
lines = data.splitlines()

# Write the data to a CSV file
with open('servers.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    for line in lines:
        csvwriter.writerow(line.split(','))