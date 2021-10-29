#!/usr/bin/env python3

import ipaddress
import sys

not_compress = '-c' in sys.argv
action = '-D' if '-d' in sys.argv else '-A'
chains = ('INPUT', 'FORWARD') if '-f' in sys.argv else ('INPUT', )

with open('ipv4.list') as f:
    a = [i.strip() for i in f.readlines()]
b = []
an = [
'103.252.114.0/23', '104.244.43.0/24', '104.244.46.0/24', '108.160.160.0/20',
'128.121.243.0/24', '128.242.240.0/24', '128.242.245.0/24', '157.240.0.0/19',
'162.125.32.0/24', '192.133.77.0/24', '199.59.148.0/22', '31.13.64.0/19',
'69.171.224.0/19',
]

a = ["%08x" % int(ipaddress.IPv4Address(i)) for i in a]
b = ["%032x" % int(ipaddress.IPv4Address(i)) for i in b]

for ani in an:
    ani = ipaddress.IPv4Network(ani)
    anit = ani.network_address
    while anit in ani:
        a.append(("%08x" % int(anit))[:6])
        anit += 256
b.extend(['200100000000000000000000'])

a.sort()
b.sort()

def iptables_cmd(v6, action, chain, namev6, hexstring):
    return ' '.join((
        'ip6tables' if v6 == 6 else 'iptables', action, chain,
        '-p udp --sport 53 -m string --hex-string',
        '"|00{}{}|"'.format('10' if namev6 == 6 else '04', hexstring),
        '--algo bm --from', '74' if v6 == 6 else '54', '-j DROP'))

if not_compress:
    for chain in chains:
        for i in a:
            print(iptables_cmd(4, action, chain, 4, i))
        for i in a:
            print(iptables_cmd(6, action, chain, 4, i))
        for i in b:
            print(iptables_cmd(4, action, chain, 6, i))
        for i in b:
            print(iptables_cmd(6, action, chain, 6, i))
else:
    print('for i in', *a, '; do')
    for chain in chains:
        print(' ', iptables_cmd(4, action, chain, 4, '$i'))
        print(' ', iptables_cmd(6, action, chain, 4, '$i'))
    print('done')
    print('for i in', *b, '; do')
    for chain in chains:
        print(' ', iptables_cmd(4, action, chain, 6, '$i'))
        print(' ', iptables_cmd(6, action, chain, 6, '$i'))
    print('done')
