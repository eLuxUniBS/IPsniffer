from ipsniffer import IPsniffer
import time
import datetime as dt

iface = "enp0s31f6"


def test_sniffer():
    snffer = IPsniffer("test", iface=iface, filter="", count=3)
    snffer.start()
    snffer.p.join()
    assert snffer.buffer.qsize() == 3


def test_restart():
    snffer = IPsniffer("test", iface=iface, filter="", count=3)
    snffer.start()
    snffer.kill()
    time.sleep(0.5)
    while not snffer.buffer.empty():
        snffer.buffer.get_nowait()
    snffer.start()
    snffer.p.join()
    assert snffer.buffer.qsize() == 3


def test_write_pcap():
    snffer = IPsniffer("test", iface=iface, filter="")
    min = 0.1
    snffer.start()
    tstart = dt.datetime.now()
    snffer.save_pcap_in_interval("test.pcap", min)
    tend = dt.datetime.now()
    snffer.kill()
    assert ((tend - tstart) - dt.timedelta(minutes=min)).total_seconds() < 1


def test_offline():
    sniffer = IPsniffer('test_offline', iface=None, filter=None, offline='/home/paolo/CSCS-TEMP/ns.cap-modbus.pcap')
    sniffer.start()
    time.sleep(1)
    sniffer.kill()
    assert sniffer.buffer.qsize() != 0


def test_getpkt():
    count = 5
    sniffer = IPsniffer('test_offline', iface=None, filter='tcp and dst port 502', count=count,offline='/home/paolo/CSCS-TEMP/ns.cap-17-00.pcap',)
    sniffer.start()
    # sniffer.kill()
    sniffer.p.join()
    ml = list()
    while sniffer.buffer.qsize() != 0:
        pkt = sniffer.buffer.get()
        print pkt.show()
        ml.append(pkt)
    assert len(ml) == count
