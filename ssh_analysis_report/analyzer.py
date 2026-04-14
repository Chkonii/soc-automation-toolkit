import csv
from datetime import datetime, timedelta
from itertools import count
import time



def analyze_with_python(file_path, ip_threshold, user_threshold, burst_threshold, burst_window):

    failed_ip = {}
    failed_user = {}
    all_failures = [] 

    
    with open(file_path, mode="r") as file:
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

   
    failures_by_ip = {}
    for row in all_failures:
        ip = row["IP_Address"]
        row["Math_Time"] = datetime.strptime(f"{row['Date']} {row['Time']}", "%Y-%m-%d %H:%M:%S")

        if ip not in failures_by_ip:
            failures_by_ip[ip] = []
        failures_by_ip[ip].append(row)

    
    burst_alerts = []
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
                burst_alerts.append(f"BURST: {ip} had {burst_count} failures within {burst_window}s starting at {failures[i]['Time']}")
                break


    report = ""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report += f"SOC analyst report\n"
    report += f"Report generated {now}\n"
    report += f"Log file analyzed: {file_path}\n"

    report += f"Total failed attempts: {len(all_failures)}\n" 
    report += "=" * 60 + "\n\n"

    for ip, count in failed_ip.items():
        if count >= ip_threshold:
            report += f"Critical {ip_threshold} or more failed ips: {ip} - {count}\n"
    
    report += "=" * 60 + "\n\n"

    for user, count in failed_user.items():
        if count >= user_threshold:
            report += f"Alert: {user} - {count} Failed attempts\n" 

    report += "=" * 60 + "\n\n"

    for alert in burst_alerts:
        report += alert + "\n"

    report_data = {
        "metadata": {
            "File_Analyzed": file_path,
            "Report_Created": now
        },
        "Total_Failures": len(all_failures),
        "Critical_IPs": {ip: count for ip, count in failed_ip.items() if count >= ip_threshold},
        "Targeted_Users": {user: count for user, count in failed_user.items() if count >= user_threshold},
        "Burst_Attacks": burst_alerts 
    }

    return report, report_data


if __name__ == "__main__":
    test_text, test_json = analyze_with_python("Auth_log_advanced.csv", 5, 3, 4, 10)
    print("_____Text Output")
    print(test_text)
    print("JSON  Output")
    print(test_json)

