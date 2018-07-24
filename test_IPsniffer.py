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
    time.sleep(2)
    while not snffer.buffer.empty():
        snffer.buffer.get_nowait()
    snffer.start()
    snffer.p.join()
    assert snffer.buffer.qsize() == 3


def test_write_pcap():
    snffer = IPsniffer("test", iface=iface, filter="")
    min=0.1
    snffer.start()
    tstart=dt.datetime.now()
    snffer.save_pcap_in_interval("test.pcap",min)
    tend = dt.datetime.now()
    assert ((tend-tstart)-dt.timedelta(minutes=min)).total_seconds()<1