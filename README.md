# Arpspoof
this is a arpspoof tool on linux, type `arpspoof --help` to see usage

# Turn on ip forwarding
**on windows**: `Open regedit,setting HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\ Services\Tcpip\Parameters\IPEnableRouter to turn on windows ip forwarding`

**on linux**: `echo 1 > /proc/sys/net/ipv4/ip_forward`
