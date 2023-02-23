import requests
import os

def Dump(domain):

    response = requests.head(f"https://{domain}")
    header_info = response.headers

    with open(f"./scans/HEADERS/{domain}.txt", "w") as f:
        for key, value in header_info.items():
            f.write(f"{key}: {value}\n")

def WebService(domain):

    response = requests.head(f"https://{domain}")
    header_info = response.headers.get('Server')
    print(f"[KSVD] WebService Detected: {header_info}")
