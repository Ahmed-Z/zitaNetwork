import subprocess,re


cmd = subprocess.check_output('ip r | grep default',shell = True, stderr=None)
result = cmd.split()
gateway = str(result[2].decode('utf-8'))
interface = str(result[4].decode('utf-8'))
cmd = subprocess.check_output('ip r | grep link',shell = True, stderr=None)
result = cmd.split()
network = str(result[0].decode('utf-8'))
localIp = str(result[8].decode('utf-8'))
prefix = network.split('/')[1]

res = subprocess.check_output(["ifconfig",interface])
mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w",res.decode("utf-8")).group(0)