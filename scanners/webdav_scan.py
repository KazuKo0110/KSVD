import requests
import os

def Scan(domain):
    with open(f"./scans/WEBDAV/{domain}.txt", "w") as f:
        f.write('{:<15} {:<45} {:<15} \n'.format('Domain', 'Payload', 'WEBDAV'))
        f.write('='*66+'\n')
        if os.system("curl -X DELETE {domain}".format(domain)):
            print("[KSVD] WEBDAV VULNERABILITY")
            if os.system("curl -T ../payloads/webdav.txt {domain}".format(domain)):
                print("[KSVD] WEBDAV VULNERABILITY UPLOAD")