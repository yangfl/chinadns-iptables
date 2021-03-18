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
'108.160.160.0/20', '31.13.64.0/19', '69.171.224.0/19',
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
        '--algo bm --from',
        '74' if v6 == 6 else '54',
        '-j DROP'))

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
