#gnlSniffer

This project is a simple sniffer used to capture local network packets.

## How to compile:

gcc gnlSniffer.c -o sniffer

## How to execute:

ifconfig eth0 promisc
./sniffer -i eth0

OBS: eth0 is the active network interface

Sniffer options and execution modes are defined in help:

./sniffer -help
