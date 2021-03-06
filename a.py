#!/usr/bin/env python3

import ipaddress
import sys

compress = '-c' in sys.argv
action = '-D' if '-d' in sys.argv else '-A'
chains = ('INPUT', 'FORWARD') if '-f' in sys.argv else ('INPUT', )

a = [
'8.7.198.45',
'8.7.198.46',
'31.13.64.1',
'31.13.64.33',
'31.13.64.35',
'31.13.64.49',
'31.13.65.1',
'31.13.65.17',
'31.13.65.18',
'31.13.66.1',
'31.13.66.6',
'31.13.66.23',
'31.13.68.1',
'31.13.68.22',
'31.13.69.33',
'31.13.69.86',
'31.13.69.129',
'31.13.69.160',
'31.13.70.1',
'31.13.70.20',
'31.13.71.7',
'31.13.71.23',
'31.13.72.1',
'31.13.72.17',
'31.13.72.23',
'31.13.72.34',
'31.13.72.54',
'31.13.73.1',
'31.13.73.17',
'31.13.73.23',
'31.13.74.1',
'31.13.74.17',
'31.13.75.17',
'31.13.75.18',
'31.13.76.8',
'31.13.76.16',
'31.13.77.33',
'31.13.77.35',
'31.13.77.55',
'31.13.78.65',
'31.13.78.66',
'31.13.79.1',
'31.13.79.17',
'31.13.80.1',
'31.13.80.17',
'31.13.81.1',
'31.13.81.17',
'31.13.82.1',
'31.13.82.17',
'31.13.82.23',
'31.13.83.1',
'31.13.83.8',
'31.13.83.16',
'31.13.84.1',
'31.13.84.8',
'31.13.84.16',
'31.13.85.1',
'31.13.85.8',
'31.13.85.16',
'31.13.86.1',
'31.13.86.8',
'31.13.86.16',
'31.13.97.245',
'31.13.97.248',
'46.82.174.68',
'46.82.174.69',
'59.24.3.173',
'59.24.3.174',
'64.13.192.74',
'64.13.192.76',
'64.13.232.149',
'66.220.146.94',
'66.220.147.11',
'66.220.147.44',
'66.220.147.47',
'66.220.149.18',
'66.220.149.32',
'66.220.149.99',
'66.220.151.20',
'66.220.152.17',
'66.220.152.28',
'66.220.155.12',
'66.220.155.14',
'66.220.158.32',
'67.15.100.252',
'67.15.129.210',
'67.228.37.26',
'67.228.74.123',
'67.228.102.32',
'67.228.126.62',
'67.228.221.221',
'67.228.235.91',
'67.228.235.93',
'69.63.176.15',
'69.63.176.59',
'69.63.176.143',
'69.63.178.13',
'69.63.180.173',
'69.63.181.11',
'69.63.181.12',
'69.63.184.14',
'69.63.184.30',
'69.63.184.142',
'69.63.186.30',
'69.63.186.31',
'69.63.187.12',
'69.63.189.16',
'69.63.190.26',
'69.171.224.12',
'69.171.224.40',
'69.171.224.85',
'69.171.225.13',
'69.171.227.37',
'69.171.228.20',
'69.171.228.74',
'69.171.229.11',
'69.171.229.28',
'69.171.229.73',
'69.171.230.18',
'69.171.232.21',
'69.171.233.24',
'69.171.233.33',
'69.171.233.37',
'69.171.234.18',
'69.171.234.29',
'69.171.234.48',
'69.171.235.16',
'69.171.235.64',
'69.171.235.101',
'69.171.237.16',
'69.171.237.26',
'69.171.239.11',
'69.171.240.27',
'69.171.242.11',
'69.171.242.30',
'69.171.244.11',
'69.171.244.12',
'69.171.244.15',
'69.171.245.49',
'69.171.245.53',
'69.171.245.84',
'69.171.246.9',
'69.171.247.20',
'69.171.247.32',
'69.171.247.71',
'69.171.248.65',
'69.171.248.112',
'69.171.248.128',
'74.86.3.208',
'74.86.12.172',
'74.86.12.173',
'74.86.17.48',
'74.86.118.24',
'74.86.142.55',
'74.86.151.162',
'74.86.151.167',
'74.86.226.234',
'74.86.228.110',
'74.86.235.236',
'75.126.2.43',
'75.126.33.156',
'75.126.115.192',
'75.126.124.162',
'75.126.135.131',
'75.126.150.210',
'75.126.164.178',
'75.126.215.88',
'78.16.49.15',
'88.191.249.182',
'88.191.249.183',
'88.191.253.157',
'93.46.8.89',
'93.46.8.90',
'173.252.73.48',
'173.252.100.21',
'173.252.100.32',
'173.252.102.16',
'173.252.102.241',
'173.252.103.64',
'173.252.110.21',
'174.36.196.242',
'174.36.228.136',
'174.37.54.20',
'174.37.154.236',
'174.37.175.229',
'199.16.156.7',
'199.16.156.40',
'199.16.158.190',
'199.59.148.14',
'199.59.148.97',
'199.59.148.140',
'199.59.148.209',
'199.59.149.136',
'199.59.149.244',
'199.59.150.11',
'199.59.150.49',
'203.98.7.65',
'205.186.152.122',
'208.43.170.231',
'208.43.237.140',
'208.101.21.43',
'208.101.48.171',
'208.101.60.87',
'243.185.187.39'
]
b = [
'10::2222',
'21:2::2',
'101::1234',
'2001::212',
'2001:da8:112::21ae',
'2123::3e12',
'200:2:253d:369e::',
'200:2:4e10:310f::',
'200:2:2e52:ae44::',
'200:2:807:c62d::',
'200:2:cb62:741::',
'200:2:f3b9:bb27::',
'200:2:5d2e:859::',
'200:2:9f6a:794b::',
'200:2:3b18:3ad::',
'50a7:26ed::64:ceef:0:0'
]

a = ["%08x" % int(ipaddress.IPv4Address(i)) for i in a]
b = ["%032x" % int(ipaddress.IPv6Address(i)) for i in b]

def iptables_cmd(v6, action, chain, namev6, hexstring):
    return ' '.join((
        'ip6tables' if v6 == 6 else 'iptables', action, chain,
        '-p udp --sport 53 -m string --hex-string',
        '"|00{}{}|"'.format('10' if namev6 == 6 else '04', hexstring),
        '--algo bm --from',
        '74' if v6 == 6 else '54',
        '-j DROP'))

if not compress:
    for chain in chains:
        for i in a:
            print(iptables_cmd(4, action, chain, 4, i))
        for i in a:
            print(iptables_cmd(6, action, chain, 4, i))
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
        print(' ', iptables_cmd(6, action, chain, 6, '$i'))
    print('done')
