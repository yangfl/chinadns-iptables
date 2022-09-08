#!/usr/bin/env python3

import ipaddress
import sys


not_compress = '-c' in sys.argv
delete = '-d' in sys.argv
nftables = True
if nftables:
    chains = ['input', 'forward'] if '-f' in sys.argv else ['input']
else:
    chains = ['INPUT', 'FORWARD'] if '-f' in sys.argv else ['INPUT']


with open('ipv4.list') as f:
    ipv4reps = [i.strip() for i in f.readlines()]
ipv4reps.append('0.0.0.0')
ipv6reps = ['fe80::1']
ipv4nets = [
'103.252.114.0/23', '104.244.43.0/24', '104.244.46.0/24', '108.160.160.0/20',
'128.121.243.0/24', '128.242.240.0/24', '128.242.245.0/24', '157.240.0.0/19',
'162.125.32.0/24', '192.133.77.0/24', '199.59.148.0/22', '31.13.64.0/19',
'69.171.224.0/19',
]

ipv4hexs = ['%08x' % int(ipaddress.IPv4Address(i)) for i in ipv4reps]
ipv6hexs = ['%032x' % int(ipaddress.IPv6Address(i)) for i in ipv6reps]

for ipv4net in ipv4nets:
    ipv4net = ipaddress.IPv4Network(ipv4net)
    ipv4 = ipv4net.network_address
    while ipv4 in ipv4net:
        ipv4hexs.append(('%08x' % int(ipv4))[:6])
        ipv4 += 256
ipv6hexs.extend(['200100000000000000000000'])

ipv4hexs.sort()
ipv6hexs.sort()


def iptables_cmd_ipver(ipver, delete, chain, dnstype, hexstring):
    return ' '.join([
        'ip6tables' if ipver == 6 else 'iptables',
        '-D' if delete else '-A',
        chain,
        '-p udp --sport 53 -m string --hex-string',
        f'"|00{"10" if dnstype == 6 else "04"}{hexstring}|"',
        '--algo bm --from', '74' if ipver == 6 else '54', '-j DROP'])


def iptables_cmd(delete, chain, dnstype, hexstring):
    return '\n'.join(
        iptables_cmd_ipver(ipver, delete, chain, dnstype, hexstring)
        for ipver in [4, 6])


def nftables_cmd(delete, chain, dnstype, hexstring):
    return ' '.join([
        'nft', 'delete' if delete else 'add', 'rule',
        'inet', 'filter', chain,
        'udp sport 53 @th,264,1000',
        f'"0x00{"10" if dnstype == 6 else "04"}{hexstring}"',
        'drop'])


tables_cmd = nftables_cmd if nftables else iptables_cmd

if not_compress:
    for chain in chains:
        for i in ipv4hexs:
            print(tables_cmd(delete, chain, 4, i))
        for i in ipv6hexs:
            print(tables_cmd(delete, chain, 6, i))
else:
    print('for i in', *ipv4hexs, '; do')
    for chain in chains:
        print(' ', tables_cmd(delete, chain, 4, '$i'))
    print('done')
    print('for i in', *ipv6hexs, '; do')
    for chain in chains:
        print(' ', tables_cmd(delete, chain, 6, '$i'))
    print('done')
