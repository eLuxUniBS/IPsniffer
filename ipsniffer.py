import logging
import datetime as dt
import multiprocessing, time
from scapy.all import *

load_contrib('modbus')


class IPsniffer:
    """
    Implements a network sniffer using the scapy library.
    """

    def __init__(self, name, iface, filter, count=None, offline=None):
        """
        Inits the sniffer
        :param name: is the name assigned to the process
        :param iface:  is the interface name string
        :param filter: is the packet filter in tcpdump syntax
        :param offline: is the pcap file path from which read packets in offline mode
        """
        self.count = count
        self.name = name
        self.buffer = multiprocessing.Queue()
        self.iface = iface
        self.filter = filter
        self.p = self._set_process()
        self.p.daemon = True
        self.offline = offline

    def _sniffer(self):
        """
        Implements e sniffer to be started in background
        :return:
        """
        sniff(iface=self.iface, filter=self.filter, prn=lambda pkt: self.bufferput(pkt), store=0, count=self.count,
              offline=self.offline)

    def _set_process(self):
        """
        creates the background process
        :return:
        """
        p = multiprocessing.Process(name=self.name, target=self._sniffer)
        p.daemon = True
        return p

    def start(self):
        """
        Starts the sniffer thread in a new python process.
        :return:
        """
        print "starting IP sniffer... ",
        if self.p.exitcode is not None:
            self.p = self._set_process()
        self.p.start()
        print "started!"

    def kill(self):
        """
        Kills the sniffer thread.
        :return:
        """
        self.p.terminate()

    def restart(self):
        """Restart the background process launching kill() and start() in a row"""
        self.kill()
        self.start()

    def save_pcap_in_interval(self, pcap_path, minutes):
        """

        :param pcap_path:
        :param minutes:
        :return:
        """
        interval = dt.timedelta(minutes=minutes)
        tstart = dt.datetime.now()

        while dt.datetime.now() - tstart < interval:
            try:
                wrpcap(pcap_path, self.buffer.get_nowait())
            except Exception as e:
                pass

    def send(self, pkt):
        """
        Send a packet at layer 3
        :param pkt: the packet to be sent
        :return: Nothing
        """
        send(pkt)

    # fixme delete
    def read_pcap(self, pcap_file):
        """ Read packets from a .pcap file and put them in the IPsniffer buffer as they were sniffed from the network"""
        loader = multiprocessing.Process(name='pcapLoader', target=self._read_pcap_worker, args=(pcap_file,))
        loader.start()

    def _read_pcap_worker(self, pcap_file):
        """ Read_pcap worker"""
        packets = rdpcap(pcap_file)
        for pkt in packets:
            self.buffer.put(pkt)

    def buffer_get(self):
        return self.buffer.get()

    def bufferput(self, k):
        # print 'put'
        # if k.haslayer(TCP):
        #     if k[TCP].dport ==502:
        self.buffer.put(k)
