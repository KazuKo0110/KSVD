import sys
import dns.resolver

def Dump(domain):

    resolver = dns.resolver.Resolver()
    with open(f'./scans/DNS/{domain}.txt', 'w') as f:
        
        f.write('{:<15} {:<15} \n'.format('Domain', 'MX Records'))
        f.write('='*45+'\n')

        try:
            mx_records = resolver.query(domain, 'MX')
            for rdata in mx_records:
                f.write('{:<15} {:<15}\n'.format(domain, str(rdata.exchange)))
        except dns.resolver.NoAnswer:
            pass
            
        f.write('\n{:<15} {:<15} \n'.format('Domain', 'Name Server'))
        f.write('='*45+'\n')

        try:
            ns_records = resolver.query(domain, 'NS')
            for rdata in ns_records:
                f.write('{:<15} {:<15}\n'.format(domain, str(rdata.target)))
        except dns.resolver.NoAnswer:
            pass

        try:
            cname_records = resolver.query(domain, 'CNAME')
            for rdata in cname_records:
                f.write('{:<15} {:<15}\n'.format(domain, str(rdata.target)))
        except dns.resolver.NoAnswer:
            pass
