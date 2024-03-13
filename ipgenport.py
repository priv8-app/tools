# Author : Priv8 Tools

import random
import re
import sys

def validate_ip(ip):
    pattern = re.compile(
        "^("
        "2(5[0-5]|[0-4]\d)|"
        "1\d{2}|"
        "[1-9]?\d)"
        "(\.(2(5[0-5]|[0-4]\d)|1\d{2}|[1-9]?\d)){3}$"
    )

    if pattern.match(ip):
        return True
    else:
        return False

# Check if command line arguments are provided
if len(sys.argv) != 3:
    print("Please provide the filename and number of IPs to generate.")
    sys.exit(1)

filename = sys.argv[1]
num_ips = int(sys.argv[2])

ip_addresses = set()

while len(ip_addresses) < num_ips: # Jumlah IP Di Generate
    ip = (
        str(random.randint(1, 255))
        + "."
        + str(random.randint(0, 255))
        + "."
        + str(random.randint(0, 255))
        + "."
        + str(random.randint(0, 255))
    )
    if validate_ip(ip):
        ip_addresses.add(ip)

# Save IP addresses to file with port 8080
with open(filename, "w") as file:
    for ip in ip_addresses:
        file.write(ip + "\n")