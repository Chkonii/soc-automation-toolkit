import csv
from datetime import datetime, timedelta
from itertools import count
import time

failed_ip = {}
failed_user = {}
all_failures = []

with open("Auth_log_advanced.csv", mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        if row["Status"] == "Failed password":
            unknwon_ip = row['IP_Address']

            if unknwon_ip in failed_ip:
                failed_ip[unknwon_ip] += 1
            else:
                failed_ip[unknwon_ip] = 1
            
            target_user = row["User"]
            if target_user in failed_user:
                failed_user[target_user] += 1
            else:
                failed_user[target_user] = 1

            all_failures.append(row)

for ip, count in failed_ip.items():      
    if count >= 5:
        print(f"Critical 5 or more failed ips: {ip} - {count}")

for user, count in failed_user.items():
    if count >= 3:
        print(f"ALERT: {user} - {count} failed attempts")

            


#Brute force detection


burst_window = 10
burst_threshold = 4

failures_by_ip = {}
for row in all_failures:
    ip = row["IP_Address"]

    row["Math_Time"] = datetime.strptime(f"{row["Date"]} {row["Time"]}", "%Y-%m-%d %H:%M:%S")

    if ip not in failures_by_ip:
        failures_by_ip[ip] = []
    failures_by_ip[ip].append(row)


for ip, failures in failures_by_ip.items():
    for i in range(len(failures)):
        burst_count = 1
        time_start = failures[i]["Math_Time"]
        for j in range(i + 1, len(failures)):
             time_current = failures[j]["Math_Time"]

             if (time_current - time_start).total_seconds() <= burst_window:
                burst_count += 1
             else:
                break

        if burst_count >= burst_threshold:
            print(f"BURST: {ip} had {burst_count} failures within {burst_window}s starting at {failures[i]['Time']}")
            break


with open("Report.txt", "w") as f:


    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"SOC analysis report\n")
    f.write(f"Report generated {now}\n")
    f.write(f"Log file analyzed: Auth_log_advanced.csv\n")
    f.write(f"Total failed attempts: {len(all_failures)}\n")
    f.write("-" * 50 + "\n\n")

    for ip, count in failed_ip.items():
        if count >= 5:
            f.write(f"Critical 5 or more failed ips: {ip} - {count}\n")

    for user, count in failed_user.items():
        if count >= 3:
            f.write(f"ALERT: {user} - {count} failed attempts\n")

    for ip, failures in failures_by_ip.items():
        for i in range(len(failures)):
            burst_count = 1
            time_start = failures[i]["Math_Time"]
            for j in range(i + 1, len(failures)):
                time_current = failures[j]["Math_Time"]
                if (time_current - time_start).total_seconds() <= burst_window:
                    burst_count += 1
                else:
                    break
            if burst_count >= burst_threshold:
                f.write(f"BURST: {ip} had {burst_count} failures within {burst_window}s starting at {failures[i]['Time']}\n")
                break
