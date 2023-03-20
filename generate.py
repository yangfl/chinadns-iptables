#!/usr/bin/env python3

from collections import Counter
import ipaddress
import sys
from typing import Literal


not_compress = '-c' in sys.argv
to_delete = '-d' in sys.argv
use_nftables = False
if use_nftables:
    chains = ['input', 'forward'] if '-f' in sys.argv else ['input']
else:
    chains = ['INPUT', 'FORWARD'] if '-f' in sys.argv else ['INPUT']


with open('ipv4.list') as f:
    ipv4reps = [i.strip() for i in f.readlines()]
ipv4reps.append('0.0.0.0')
ipv4addrs = [ipaddress.IPv4Address(i) for i in ipv4reps]

ipv4nets = [ipaddress.IPv4Network((net, 24)) for net, cnt in Counter(
    int(addr) & 0xffffff00 for addr in ipv4addrs).items() if cnt >= 8]
_ipv4nets = set(int(net.network_address) for net in ipv4nets)
print('filter net', *sorted(ipv4nets))
print()

ipv4hexs = ['%06x' % (int(net.network_address) >> 8) for net in ipv4nets]
for addr in ipv4addrs:
    net = int(addr) & 0xffffff00
    if net not in _ipv4nets:
        ipv4hexs.append('%08x' % int(addr))
ipv4hexs.sort()


ipv6reps = ['fe80::1']
ipv6addrs = [ipaddress.IPv6Address(i) for i in ipv6reps]

ipv6hexs = ['%032x' % int(i) for i in ipv6addrs]
ipv6hexs.extend(['200100000000000000000000', '83faceb00c000025de'])
ipv6hexs.sort()


def iptables_cmd_ipver(
        ipver: Literal[4, 6], to_delete: bool, chain,
        dnstype: Literal[4, 6], mask):
    return ' '.join([
        'ip6tables' if ipver == 6 else 'iptables',
        '-D' if to_delete else '-A',
        chain,
        '-p udp --sport 53 -m string --hex-string',
        f'"|00{"10" if dnstype == 6 else "04"}{mask}|"',
        '--algo bm --from', '74' if ipver == 6 else '54', '-j DROP'])


def iptables_cmds(to_delete: bool, chain, dnstype: Literal[4, 6], mask):
    return [
        iptables_cmd_ipver(ipver, to_delete, chain, dnstype, mask)
        for ipver in [4, 6]]


def nftables_cmds(to_delete: bool, chain, dnstype: Literal[4, 6], mask):
    return [' '.join([
        'nft', 'delete' if to_delete else 'add', 'rule',
        'inet', 'filter', chain,
        'udp sport 53 @th,264,1000',
        f'"0x00{"10" if dnstype == 6 else "04"}{mask}"',
        'drop'])]


tables_cmds = nftables_cmds if use_nftables else iptables_cmds

if not_compress:
    for chain in chains:
        for i in ipv4hexs:
            for cmd in tables_cmds(to_delete, chain, 4, i):
                print(' ', cmd)
        for i in ipv6hexs:
            for cmd in tables_cmds(to_delete, chain, 6, i):
                print(' ', cmd)
else:
    print('for i in', *ipv4hexs, '; do')
    for chain in chains:
        for cmd in tables_cmds(to_delete, chain, 4, '$i'):
            print(' ', cmd)
    print('done')
    print('for i in', *ipv6hexs, '; do')
    for chain in chains:
        for cmd in tables_cmds(to_delete, chain, 6, '$i'):
            print(' ', cmd)
    print('done')
