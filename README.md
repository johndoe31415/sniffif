# sniffif
When you want to quickly sniff network traffic of a host on a dedicated network
adapter (e.g., an external USB adapter), you have to setup DNS redirection, a
DHCP server on that NIC, NAT and sniff with tcpdump all the traffic you get.
With sniffif, this is simplified to one script call (after it's been setup with
the config file).

## License
GNU GPL-3.
