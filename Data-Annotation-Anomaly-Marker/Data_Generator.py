import csv
import random
from datetime import datetime, timedelta

def generate_raw_logs(filename="raw_network_logs.csv",count=40):
    standard_ips=["127.0.0.1","192.168.1.1","10.0.0.15","8.8.8.8","192.0.2.1"]
    sus_ips=["185.220.101.5","45.142.195.34","91.240.118.212","193.239.147.14"]
    protocols=["TCP","UDP","ICMP","HTTP","HTTPS"]

    with open(filename, mode='w', newline='') as file :
        writer=csv.writer(file)
        writer.writerow(["Timestamp","Source_IP","Dest_Port","Protocol","Bytes_sent"])

        current_time=datetime.now()
        for i in range(count):
            timestamp=(current_time - timedelta(minutes = i * 3)).strftime("%Y-%m-%d %H:%M:%S")
            protocol=random.choice(protocols)
            if random.random()<0.25:
                src_ip=random.choice(sus_ips)
                port=random.choice([22,23,80,443,4444])
                bytes_sent=random.randint(600000,2500000)
            else:
                src_ip=random.choice(standard_ips)
                port=random.choice([80,443,8080,53,21])
                bytes_sent=random.randint(200,8000)
            writer.writerow([timestamp,src_ip,port,protocol,bytes_sent])
    print(f"Generated {count} raw network logs in {filename}")

generate_raw_logs()
