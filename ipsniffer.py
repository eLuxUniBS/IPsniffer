import logging
import multiprocessing, time
from scapy.all import *
# # necessary to configure scapy to sniff with pcap (and consider the VLAN header)
# conf.use_pcap = True
# import scapy.arch.pcapdnet
import netifaces


class ipsniffer:
    """
    Implements a network sniffer using the scapy library.
    """

    # class PacketHandler:
    #     """
    #     defines the handler of the packets sniffed by the worker
    #     """
    #
    #     def __init__(self, filter, iface, buffer):
    #         self.q = buffer
    #         self.filter = filter
    #         self.iface = iface
    #
    #     def get_pkt(self, pkt):
    #         self.q.put(pkt)
    #         # print "packet received "+str(self.q.qsize())

    def __init__(self, name, iface, filter):
        self.name = name
        self.buffer = multiprocessing.Queue()
        self.iface = iface
        self.filter = filter
        # self.handler = self.PacketHandler(filter, iface, self.buffer)
        self.p = self._set_process()
        self.p.daemon = True

    def _set_process(self):
        return multiprocessing.Process(name=self.name, target=self._sniffer, args=(self.filter, self.iface, self.buffer,))

    def _sniffer(self, filter, iface, mybuffer):
        """
        Implements e sniffer to be started in background
        :return:
        """
        print "worker started"
        # while True:
        #     buffer.put("a")
        #     time.sleep(1)
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


if __name__ == '__main__':
    pass
