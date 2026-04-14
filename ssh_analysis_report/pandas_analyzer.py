import pandas as pd
from datetime import datetime





def analyze_with_pandas(file_path, ip_threshold, user_threshold, burst_threshold, burst_window):

    df = pd.read_csv(file_path)

    failed_df = df[df["Status"] == "Failed password"].copy()

    failed_df["Timestamp"] = pd.to_datetime(failed_df["Date"] + " " + failed_df["Time"])
    failed_df.set_index("Timestamp", inplace=True)
    failed_df.sort_index(inplace=True)    

    total_failed = len(failed_df)
    total_logs = len(df)

    ip_count = failed_df["IP_Address"].value_counts()
    suspicious_ips = ip_count[ip_count >= ip_threshold]


    user_count = failed_df["User"].value_counts()
    suspicious_users = user_count[user_count >= user_threshold]

    burst_window_str = f"{burst_window}s"


    rolling_counts = failed_df.groupby("IP_Address").rolling(burst_window_str)["User"].count()
    bursts = rolling_counts[rolling_counts >= burst_threshold]
    bursts_ips = bursts.index.get_level_values("IP_Address").unique()


    report = ""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    report += "__________________Brute force detection__________________\n"
    report += f"Report generated {now}\n"
    report += f"Log files analyzed {file_path}\n"
    report += f"Total log entires {total_logs}\n"
    report += f"Total Failed logs {total_failed}\n"
    report += f"Failure rate: {round(total_failed / total_logs * 100, 1)}%\n"
    report += "=" * 60 + "\n\n"

    report += "_____Suspicious IPs_____\n"

    for ip, count in suspicious_ips.items():
        report += f"Critical IPs {ip} - {count} failed attempts\n"

    report += "=" * 60 + "\n\n"

    report += "_____Suspicious Users_____\n"


    for user, count in suspicious_users.items():
        report += f"Suspicious Users {user} - {count} failed attempts\n"

    report += "=" * 60 + "\n\n"

    report += "_____Burst Attack_____\n"

    if len(bursts_ips) > 0:
        for ip in bursts_ips:
            ip_bursts = bursts.loc[ip]
            max_count = int(ip_bursts.max())
            report += f"BURST: {ip} had {max_count} failures within {burst_window}s window\n"
    else:
        report += "No Burst attack detected\n"

    report_data = {
        "metadata": {
            "File_Analyzed": file_path,
            "Report_Created": now
        },
        "Total_Failures": total_failed,
        "Critical_IPs": suspicious_ips.to_dict(),
        "Targeted_Users": suspicious_users.to_dict(),
        "Burst_Attacks": list(bursts_ips)
    }

    return report, report_data

if __name__ == "__main__":
    test_report = analyze_with_pandas("Auth_log_Advanced.csv", 5, 5, 4, 10)
    print(test_report)




        


 




