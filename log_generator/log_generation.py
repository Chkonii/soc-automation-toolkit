import csv
import random 
from datetime import datetime, timedelta


users = [
    "root", "admin", "dev_user", "guest", "ubuntu", "giorgi", 
    "service_account", "postgres", "oracle", "ftpuser", 
    "testuser", "backup", "webmaster", "dbadmin"
]

bad_ips = [
    "103.45.67.89", "45.33.22.11", "201.11.9.88", "185.22.33.44", 
    "92.118.38.55", "178.62.10.11", "89.248.165.20", "43.224.10.33", 
    "114.119.160.20", "193.188.22.11"
]

good_ips = [
    "192.168.1.50", "10.0.0.15", "10.0.0.22", "192.168.1.100", 
    "192.168.1.105", "10.0.0.35", "10.0.0.88", "172.16.0.5", 
    "172.16.0.12", "172.16.0.55"
]



with open("Auth_log_Advanced.csv", mode="w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow(["Date", "Time", "Service", "PID", "Status", "User", "IP_Address", "Port"])

    current_time = datetime.now() - timedelta(hours=2)

    i = 0
    while i < 100:
        current_time += timedelta(seconds=random.randint(1, 39))

        if random.random() < 0.2:
            burst_ip = random.choice(bad_ips)
            burst_user = random.choice(["root", "admin", "ubuntu", "postgres"])
            burst_port = random.randint(30000, 65000)


            for _ in range(random.randint(5, 10)):
                current_time += timedelta(seconds=random.randint(1, 4))

                log_date = current_time.strftime("%Y-%m-%d")
                log_time = current_time.strftime("%H:%M:%S")
                pid = random.randint(10000, 20000)
                writer.writerow([log_date, log_time, "sshd", pid, "Failed password", burst_user, burst_ip, burst_port])
                i += 1

        else:
            log_date = current_time.strftime("%Y-%m-%d")
            log_time = current_time.strftime("%H:%M:%S")
            pid = random.randint(10000, 20000)


            if random.random() < 0.5:
                user = random.choice(["root", "testuser", "webmaster", 'admin'])
                ip = random.choice(bad_ips)
                status = "Failed password"
                port = random.randint(30000, 65000)
            else:
                user = random.choice(users)
                ip = random.choice(good_ips)
                status = random.choice(["Accepted password", "Accepted publickey"])
                port = random.randint(50000, 60000)

            writer.writerow([log_date, log_time, "sshd", pid, status, user, ip, port])
            i += 1

print("Created realistic logs")  

