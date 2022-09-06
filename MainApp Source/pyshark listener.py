import pyshark
import os
import sys
import traceback
import time
import threading
import subprocess

warband_path = os.path.join(os.getcwd(), "..", "mb_warband_wse2_dedicated.exe")
ip_list_file_name = os.path.join("pyshark allowed ip list.txt")
logs_file_name = os.path.join("pyshark logs.txt")

create_rule = "netsh advfirewall firewall add rule name={rule_name} dir=in action=allow program=\"{program}\" protocol=udp localport=7240 remoteip=192.168.1.1"
update_rule = "netsh advfirewall firewall set rule name={rule_name} new remoteip={ip_addresses}"
query_rules = ["powershell", "Get-NetFirewallPortFilter -Protocol UDP | Where { $_.localport -eq '7240' } | Get-NetFirewallRule | select DisplayName"]
##print([rule[:-1].strip() for rule in subprocess.check_output(query_rules, shell=True).decode().split("\n")[3:-3]])
##create_rule = "gcloud compute --project=legacy-of-valors-official firewall-rules create {rule_name} --direction=INGRESS --priority=1000 --network=default --action=ALLOW --rules=tcp:7240,udp:7240 --source-ranges=192.168.1.1"
##update_rule = "gcloud compute firewall-rules update {rule_name} --source-ranges={ip_addresses}"


interface = "Ethernet"
knocking_port = "25556"
self_ip_address = "91.151.94.225"

def logging_print(*string, end = "\n", sep = " "):
    print(*string, end = end, sep = sep)
    
    file = open(logs_file_name, "a")
    old_stdout = sys.stdout
    sys.stdout = file
    print(*string, end = end, sep = sep)
    sys.stdout = old_stdout
    file.close()

def get_ip_adresses():
    with open(ip_list_file_name, "r") as file:
        return file.read().split("\n")

def split_ip_list(ip_adresses):
    ip_lists = []
    while len(ip_adresses) > 256:
        ip_lists.append(ip_adresses[:256])
        ip_adresses = ip_adresses[256:]
    ip_lists.append(ip_adresses)
    return ip_lists

def gcloud_thread(i, ip_list, rules):
    try:
        rule_name = "allow-main-filter-{count}".format(count = i)
        if not rule_name in rules:
            os.system(create_rule.format(rule_name = rule_name, program = warband_path))
        os.system(update_rule.format(rule_name = rule_name, ip_addresses = ",".join(ip_list), program = warband_path))
    except:
        logging_print(traceback.format_exc(), "-gcloud thread {}".format(i))

def gcloud_updater():
    current_ip_list = []
    while True:
        try:
            ip_adresses = get_ip_adresses()
            threads = []
            if ip_adresses != current_ip_list:
                logging_print("Updating Gcloud...")
                rules = [rule[:-1].strip() for rule in subprocess.check_output(query_rules, shell=True).decode().split("\n")[3:-3]]
##                rules = [str(rule).split(" ")[0] for rule in os.popen("gcloud compute firewall-rules list").read().split("\n")]
                for i, ip_list in enumerate(split_ip_list(ip_adresses)):
                    thread = threading.Thread(target = gcloud_thread, args = (i, ip_list, rules))
                    thread.start()
                    threads.append(thread)
                for thread in threads:
                    thread.join()
                current_ip_list = ip_adresses
                del threads
            else:
                time.sleep(1)
        except:
            logging_print(traceback.format_exc(), "-gcloud updater")

try:
    threading.Thread(target = gcloud_updater).start()
    capture = pyshark.LiveCapture(interface, bpf_filter = "port {}".format(knocking_port))
    logging_print("Started capturing from interface: '{}', port: '{}'".format(interface, knocking_port))
    for packet in capture:
        ip_address = packet.ip.src
        if ip_address == self_ip_address: continue
        if not ip_address in get_ip_adresses():
            logging_print("Verified new player: {}".format(ip_address))
            with open(ip_list_file_name, "a") as ip_list_file:
                ip_list_file.write("\n" + ip_address)
except:
    logging_print(traceback.format_exc(), "-main")
