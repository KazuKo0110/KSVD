import socket
import sys

def Scan(domain):
    
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        print('Invalid domain name.')
        sys.exit(1)

    ports = range(1, 445)

    with open(f'./scans/PORTS/{domain}.txt', 'w') as f:

        f.write('{:<15} {:<15} {:<15} \n'.format('Domain', 'Port', 'Service'))
        f.write('='*45+'\n')

        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((ip_address, port))

            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = 'unknown'
                except socket.timeout:
                    pass
                except ConnectionResetError:
                    pass
                f.write('{:<15} {:<15} {:<15} \n'.format(domain, port, service))
                s.close()
