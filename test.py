import scapy.all as scapy
import netfilterqueue,subprocess
import scapy_http.http

def manage_packet(scapy_packet):
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet.haslayer(scapy.TCP):
                if scapy_packet[scapy.TCP].dport == 80:
                    print(scapy_packet.show())
                    # scapy_packet[scapy.Raw].load = re.sub("Accept-Encoding:.*?\\r\\n",'',scapy_packet[scapy.Raw].load)
                    # scapy_packet[scapy.Raw].load = re.sub("HTTP/1.1",'HTTP/1.0',scapy_packet[scapy.Raw].load) 
                    # scapy_packet = manage_packet(scapy_packet)
                    # packet.set_payload(str(scapy_packet))   
    except Exception as e:
        print(e)
        
    try:
        if scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet.haslayer(scapy.Raw):
                # print(scapy_packet[scapy.Raw].load)
                pass
    except:
        pass

    packet.accept()

def main():

    #subprocess.call('sudo iptables -I FORWARD -j NFQUEUE --queue-num 1',shell=True)
    subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num 2',shell=True)
    subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num 2',shell=True)
            

    print('[+] iptables configured')
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(2,process_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        subprocess.call('iptables --flush',shell=True)
        print('\n[+] iptables flushed.')


main()