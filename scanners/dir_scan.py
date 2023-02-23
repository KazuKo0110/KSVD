import requests
from time import sleep

def Scan(domain):

    with open(f"./scans/DIRECTORIES/{domain}.txt", "w") as f:
        f.write("{:<15} {:<15} {:<15} \n".format("Domain", "Directory", "Response Code"))
        f.write("="*45+"\n")

    with open("./wordlists/dir_list.txt", "r") as f:

        for line in f:
            try:
                stripped = line.strip()
                response = requests.get(f"https://{domain}/{stripped}")
                if response.status_code != 404 and response.text == "404":
                    with open(f"./scans/DIRECTORIES/{domain}.txt", "a") as f:
                        f.write("{:<15} {:<15} {:<15} \n".format(domain, stripped, str(response.status_code)))
            except requests.exceptions.ConnectionError as e:
                continue