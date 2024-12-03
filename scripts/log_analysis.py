import re
from collections import defaultdict
import csv

#Count Requests per IP Address
with open('C:\\Users\\PRASAD\\log_analysis_project\\logs\\sample.log', 'r') as file:
    log_lines = file.readlines()

ip_count = defaultdict(int)

for line in log_lines:
    match = re.match(r"(\S+)\s-\s-\s", line)
    if match:
        ip_address = match.group(1)
        ip_count[ip_address] += 1

sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
print("IP Address           Request Count")
for ip, count in sorted_ips:
    print(f"{ip:20} {count}")

# Identify the Most Frequently Accessed Endpoint
endpoint_count = defaultdict(int)

for line in log_lines:
    match = re.search(r'"(?:GET|POST)\s(/[\S]*)\s', line)
    if match:
        endpoint = match.group(1)
        endpoint_count[endpoint] += 1

most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1])
print(f"Most Frequently Accessed Endpoint: {most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

# Detect Suspicious Activity
failed_logins = defaultdict(int)

for line in log_lines:
    if "401" in line or "Invalid credentials" in line:
        match = re.match(r"(\S+)\s-\s-\s", line)
        if match:
            ip_address = match.group(1)
            failed_logins[ip_address] += 1

suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > 10}
print("Suspicious Activity Detected:")
for ip, count in suspicious_ips.items():
    print(f"{ip:20} {count}")

# Output Results to Terminal
    # The code to display the results is already written in previous steps

# Save Results to CSV File
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # Write IP request counts
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in sorted_ips:
        writer.writerow([ip, count])

    # Write most accessed endpoint
    writer.writerow(["Most Accessed Endpoint", most_accessed_endpoint[0]])
    writer.writerow(["Access Count", most_accessed_endpoint[1]])

    # Write suspicious activity
    writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])

