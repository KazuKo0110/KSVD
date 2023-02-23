import requests


def Scan(domain):

    param = input("[KSVD] IDOR Parameter: ")
    with open(f'./scans/IDOR/{domain}.txt', 'w') as f:
        f.write('{:<15} {:<45} {:<15} \n'.format('Domain', 'Payload', 'IDOR'))
        f.write('='*66+'\n')

    with open("./payloads/idor.txt", "r") as f:
        try:
            for line in f:
                payload = line.strip()
                response = requests.get(f"https://{domain}{param}{payload}")
                if response.status_code != 404:
                    with open(f"./scans/IDOR/{domain}.txt", "a") as f:
                        f.write("{:<15} {:<45} {:<15} \n".format(domain, payload, "True"))
                else:
                    pass
        except requests.exceptions.ConnectionError as e:
            pass