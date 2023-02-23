import os
import sys
import argparse
import requests
import scanners.dns_scan
import scanners.port_scan
import scanners.sub_scan
import scanners.dir_scan
import scanners.webdav_scan
import scanners.head_scan
import scanners.lfi_scan
import scanners.tech_detect
import scanners.sqli_scan
import scanners.idor_scan
import scanners.xss_scan
from colorama import *

parser = argparse.ArgumentParser()
parser.add_argument(
    '-d', 
    '--domain',
    help='Specify the target domain'
)
args = parser.parse_args()

class Variables:

    global __creators__, __version__, __github__

    __creators__ = 'WarHawk & YazukoWeb'
    __version__  = '1.0.3'
    __github__   = 'github.com/KazuKo0110'

class Modules:

    def clear():
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
    
    def detect():
        if os.name == 'nt':
            return 'Windows'
        else:
            return 'Linux'

    def banner():

        __system__ = Modules.detect()

        print(f'''                            
            \`*-.                {Fore.MAGENTA}*KSVD Hunt* {Fore.RESET}
             )  _`-.                
            .  : `. .               
            : _   '  \              
            ; *` _.   `*-._         
            `-.-'          `-.         {Fore.LIGHTRED_EX}         Developers..: {__creators__} {Fore.RESET}
              ;       `       `.        {Fore.LIGHTRED_EX}        Version.....: {__version__}  {Fore.RESET}
              :.       .        \        {Fore.LIGHTRED_EX}       Github......: {__github__}   {Fore.RESET}
              . \  .   :   .-'   .         {Fore.LIGHTRED_EX}     System......: {__system__}   {Fore.RESET}
              '  `+.;  ;  '      :  
              :  '  |    ;       ;-.
              ; '   : :`-:     _.`* ;
           .*' /  .*' ; .*`- +'  `*'
           `*-*   `*-*  `*-*' 
           {Fore.LIGHTBLACK_EX}Kitty Scanner Vulnerability Detector. by WarHawk & Yazuko (BETA) {Fore.RESET}
        ''')

class Main():

    def main(domain):
        Modules.clear()
        Modules.banner()

        try:
            scanners.head_scan.WebService(domain)
            scanners.tech_detect.Detect(domain)

            print(f'{Fore.LIGHTMAGENTA_EX}\n[KSVD] Dumping DNS Records')
            scanners.dns_scan.Dump(domain)

            print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Dumping Domain Headers')
            scanners.head_scan.Dump(domain)

            print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Scanning for Open Ports and their Services')
            scanners.port_scan.Scan(domain)

            print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Bruteforcing Subdomains')
            print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Scanning for Subdomain Takeover')
            scanners.sub_scan.Scan(domain)

            print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Bruteforcing Directories')
            scanners.dir_scan.Scan(domain)

            print(f"{Fore.LIGHTMAGENTA_EX}[KSVD] Scanning for Webdav")
            scanners.webdav_scan.Scan(domain)
            
            print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Scanning for LFI')
            scanners.lfi_scan.Scan(domain)

            print(f"{Fore.LIGHTMAGENTA_EX}[KSVD] Scanning for XSS")
            scanners.xss_scan.Scan(domain)

            print(f"{Fore.LIGHTMAGENTA_EX}[KSVD] Scanning for SQLi")
            scanners.sqli_scan.Scan(domain)

            print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Scanning for IDOR')
            scanners.idor_scan.Scan(domain)
            
        except KeyboardInterrupt:
            print(f"{Fore.RED}\n[KSVD] Exiting...{Fore.RESET}")
            sys.exit()

        if os.name == 'nt':
            os.system('explorer .\scans')
        else:
            pass
        
if __name__ == '__main__':
    if args.domain:
        Main.main(args.domain)
    else:
        Modules.clear()
        Modules.banner()
        print(f'{Fore.LIGHTMAGENTA_EX}[KSVD] Syntax:  python ksvd.py -d <domain>')
        print(f'[KSVD] Example: python ksvd.py -d domain.com\n{Fore.RESET}')
