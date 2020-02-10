import scapy.all as scapy
import netfilterqueue,subprocess,re
import scapy_http.http

def manage_packet(scapy_packet):
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy_http.http.HTTPRequest):
        print("[+] HTTP request")
    elif scapy_packet.haslayer(scapy_http.http.HTTPResponse):
        if scapy_packet.haslayer(scapy.Raw): 
            print(scapy_packet[scapy.Raw].load)   





    # try:
    #     if scapy_packet.haslayer(scapy_http.http.HTTPRequest):
    #         if (scapy_packet[scapy.TCP].dport) == 80:
    #             decoded = scapy_packet[scapy_http.http.HTTPRequest].Headers.decode("utf-8")
    #             if "Accept-Encoding" in decoded :
    #                 scapy_packet[scapy_http.http.HTTPRequest].Headers = re.sub("Accept-Encoding:.*?\\r\\n",'',decoded).encode()
    #                 scapy_packet = manage_packet(scapy_packet)
    #                 packet.set_payload(str(scapy_packet))
    #                 print(scapy_packet.show())
    #     if scapy_packet.haslayer(scapy_http.http.HTTPResponse):
    #         if (scapy_packet[scapy.TCP].sport) == 80:
    #             if scapy_packet.haslayer(scapy.Raw):
    #                 pass
    # except Exception as e:
    #     print(e)


    packet.accept()

def main():

    subprocess.call('sudo iptables -I FORWARD -j NFQUEUE --queue-num 1',shell=True)
    # subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num 2',shell=True)
    # subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num 2',shell=True)


    print('[+] iptables configured')
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1,process_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        subprocess.call('iptables --flush',shell=True)
        print('\n[+] iptables flushed.')


main()