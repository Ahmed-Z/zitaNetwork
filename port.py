import socket
import concurrent.futures

# remoteServer    = str(input("Enter a remote host to scan: "))
remoteServerIP  = socket.gethostbyname("192.168.1.1")

def scan(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((remoteServerIP, port))
    if result == 0:
        print("Open Port on : "+ str(port))
    sock.close()

# port_list = list(range(1,10000))
# with concurrent.futures.ThreadPoolExecutor() as executor:
#             executor.map(scan, port_list)

target = "192.168.1.1"
target = target.split(' ')*10
print(target)