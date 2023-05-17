import requests
import subprocess
import time

def load_hosts():
    with open("./http_hosts.txt", 'r') as f:
        http_hosts = f.read().split('\n')

    with open("./https_hosts.txt", 'r') as f:
        https_hosts = f.read().split('\n')

    return (http_hosts, https_hosts)

def spawn_suricata():
    return subprocess.Popen("sudo suricata -s test.rules -i eth0", shell=True)

def gen_http_rules(http_hosts):
    global sid
    http_rule = ""
    for host in http_hosts:
        http_rule += f"alert tcp any any -> any 80 (msg: \"{host}\"; content: \"Host: \"; content: \"{host}\"; sid: {sid}; rev: 1;)\n"
        sid += 1
    return http_rule

def gen_https_rules(https_hosts):
    global sid
    https_rule = ""
    for host in https_hosts:
        https_rule += f"alert tcp any any -> any 443 (msg: \"{host}\"; content: \"{host}\"; sid: {sid}; rev: 1;)\n"
        sid += 1
    return https_rule

def write_rules(rules):
    with open("test.rules", 'w') as f:
        f.write(rules)

def test_rules(http_host, https_host, timeout=3):
    for http_host in http_hosts:
        res = requests.get(f"http://{http_host}", timeout=timeout)
        latest_log = subprocess.check_output("tail /var/log/suricata/fast.log -n 1 | awk '{print $4}'", shell=True).strip().decode()
        if latest_log != http_host:
            print(latest_log, http_host)
            return False
    for https_host in https_hosts:
        res = requests.get(f"https://{https_host}", timeout=timeout)
        latest_log = subprocess.check_output("tail /var/log/suricata/fast.log -n 1 | awk '{print $4}'", shell=True).strip().decode()
        if latest_log != https_host:
            print(latest_log, https_host)
            return False
    return True

def copy_log():
    subprocess.run("tail /var/log/suricata/fast.log -n 100 > ./fast.log", shell=True)

sid = 10000000

http_hosts, https_hosts = load_hosts()

rules = gen_http_rules(http_hosts)
rules += gen_https_rules(https_hosts)

write_rules(rules)

suricata = spawn_suricata()
time.sleep(3)
    
if test_rules(http_hosts, https_hosts) == True:
    print("Success")
    copy_log()
else:
    print("Fail")
    
suricata.terminate()
    


