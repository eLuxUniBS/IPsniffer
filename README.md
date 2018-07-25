# IPsniffer
Implements an easy way to integrate a IPsniffer inside a python progam. It is based on the scapy (https://scapy.net/) library 

### Notes: 
- tested with python 2.7
- program should be run as root to allow scapy use the network interface

## Install
- install dependecies: sudo pip install scapy
- clone the repository inside your project directory

## Usage
To a full reference of the methods parameters please refer to docstrings in code. 

```python
from ipsniffer import IPsniffer

# create a new sniffer object if count is omitted it will sniff forever
sniffer = IPsniffer("test", iface=iface, filter="", count=3)
#starts a new background process which sniffs the iface interface for packest filtered by filter (tcpdum syntax)
sniffer.start()

# terminates the sniffing process. use start() to restart it
sniffer.kill() 

# Get a packet from the sniffer buffer. buffer is a multiprocessing.Queue object
sniffer.buffer.get()

#save in the "test.pcap" file 20 packets for 20 min. The sniffer background process is unaffected by this method as well as the content of the buffer.
sniffer.save_pcap_in_interval("test.pcap",20)

```
