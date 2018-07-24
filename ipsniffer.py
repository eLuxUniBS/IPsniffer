import logging
import multiprocessing, time
from scapy.all import *

class IPsniffer:
    """
    Implements a network sniffer using the scapy library.
    """

    def __init__(self, name, iface, filter):
        """
        Inits the sniffer
        :param name: is the name assigned to the process
        :param iface:  is the interface name string
        :param filter: is the packet filter in tcpdump syntax
        """
        self.name = name
        self.buffer = multiprocessing.Queue()
        self.iface = iface
        self.filter = filter
        self.p = self._set_process()
        self.p.daemon = True

    def _set_process(self):
        """
        creates the background process
        :return:
        """
        return multiprocessing.Process(name=self.name, target=self._sniffer,
                                       args=(self.filter, self.iface, self.buffer,))

    def _sniffer(self, filter, iface, mybuffer):
        """
        Implements e sniffer to be started in background
        :return:
        """
        sniff(iface=iface, filter=filter, prn=lambda pkt: mybuffer.put(pkt), store=0)

    def start(self):
        """
        Starts the sniffer thread in a new python process.
        :return:
        """
        print "starting..."
        if self.p.exitcode is not None:
            self.p = self._set_process()
        self.p.start()
        print "started"

    def kill(self):
        """
        Kills the sniffer thread.
        :return:
        """
        self.p.terminate()
