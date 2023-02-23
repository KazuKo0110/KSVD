import requests


def Scan(domain):
    param = input("[LOTUS] LFI Parameter: ") # ?page= for example
    with open(f"./scans/LFI/{domain}.txt", "w") as f:
        f.write('{:<15} {:<45} {:<15} \n'.format('Domain', 'Payload', 'LFI'))
        f.write('='*66+'\n')

    with open("./payloads/lfi.txt", "r") as f:
        for line in f:
            payload = line.strip()
            response = requests.get(f"https://{domain}{param}/{payload}")
            if response.status_code != 404:
                if "root:" in response.content.decode():
                    with open(f"./scans/LFI/{domain}.txt", "a") as f:
                        f.write("{:<15} {:<45} {:<15} \n".format(domain, payload, "True"))
                else:
                    pass