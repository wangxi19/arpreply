# Arpreply
this is a arpspoof tool on linux, type `arpreply --help` to see usage

# Usage
```
arpreply version 1.0, release date: 2018-12-06

Usage: arpreply --help | -list | [-i interfacename] [-itval n] -rti ipaddr -rqi ipaddr [-rqm macaddr] [-q]
-list           list all interfaces
-i              specify outgoing interface
-itval          specify the interval seconds between two sending (default: 1)
--help          display help
-rti            reply to ip address
-rqi            ip address that using to reply
-rqm            mac address that using to reply
-q              quite model

example: arpreply -rti 192.168.1.123 -rqi 192.168.1.1 -rqm 00:00:00:00:00:00
just work in ipv4 networking, ipv6 is still considering
```

# Turn on ip forwarding
**on windows**: `Open regedit,setting HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\ Services\Tcpip\Parameters\IPEnableRouter value from 0 to 1 to turn on windows ip forwarding`

**on linux**: `echo 1 > /proc/sys/net/ipv4/ip_forward`
