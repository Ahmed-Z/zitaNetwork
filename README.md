<h1> zitaNetwork </h1>

 <p> A python3 framework that performs a variety of attacks in local network. </p>
 
 ![zita](https://i.imgur.com/ECd8WNj.png)


<h2>Documentation</h2>

 Type `help` to display commands.
 
- General commands

```
info                    Print basic information about the local network.
mac [spoofed_mac]       Change your current MAC address with spoofed_mac.
scan                    Scan your network for targets.
sniff                   Sniff urls and passwords of spoofed target.
jamm                    Deny internet access for all hosts on the network.
dnsspoof                Poison DNS request(s) of spoofed target. 
alert                   Display alert message for spoofed target.
target [target_ip]      Select target to perform additional attacks. 
intercept               Intercept and replace downloads of spoofed target.
```
- Target specific commands
```
spoof               Perform an ARP spoof attack.
kick                Deny internet access for target.
pscan               Scan target for open ports.
```
