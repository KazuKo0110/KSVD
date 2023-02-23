import requests


def Scan(domain):
    param = input("[KSVD] SQLI Parameter: ") # ?id= for example
    with open(f'./scans/SQLI/{domain}.txt', 'w') as f:
        f.write('{:<15} {:<45} {:<15} \n'.format('Domain', 'Payload', 'SQLI'))
        f.write('='*66+'\n')

    with open("./payloads/sqli.txt", "r") as f:
        try:
            for line in f:
                payload = line.strip()
                url = domain + param + payload
                response = requests.get(f"https://{url}")
                if 'sql syntax' in response.text.lower() or 'mysql_fetch' in response.text.lower():
                    with open(f"./scans/SQLI/{domain}.txt", "a") as f:
                        f.write("{:<15} {:<45} {:<15} \n".format(domain, payload, "True"))
                else:
                    pass
        except requests.exceptions.ConnectionError as e:
            pass
