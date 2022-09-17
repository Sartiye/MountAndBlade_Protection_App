import sys, os
import traceback
import threading
import time
import datetime
import pyshark
import ipaddress
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from module_directories import directories

#C:\Program Files\Wireshark\dumpcap -b filesize:100000 -b printname:stdout -w C:\Temp\mycap.pcap -i Wi-Fi

def check_file(directory):
    try:
        with open(directory, mode = "x", encoding = "utf-8"):
            logging_print("Created the file: ({}).".format(directory.basename()))
    except FileExistsError:
        pass

def logging_print(*string, sep = " ", end = "\n"):
    print("[{}]".format(datetime.datetime.now().strftime("%H:%M:%S")), *string, sep = sep, end = end)
    directories.logs.format(strftime = datetime.datetime.now().strftime("%Y_%m_%d"))
    check_file(directories.logs)
    file = open(directories.logs, "a", encoding="utf-8")
    old_stdout = sys.stdout
    sys.stdout = file
    print("[{}]".format(datetime.datetime.now().strftime("%H:%M:%S")), *string, sep = sep, end = end)
    sys.stdout = old_stdout
    file.close()

def string_bool_meaning(string):
    true_strings = ["1", "true", "yes", "+"]
    return string.lower() in true_strings

base_settings = {
    "google cloud" : {
        "active" : False,
    },
    "advanced firewall" : {
        "active" : False,
    },
    "pyshark" : {
    }
}

ip_lists = {"allowlist": set(), "blacklist": set()}
current_settings = base_settings.copy()
rule_uid_dict = dict() #unique ids of rule definitions.

def import_settings():
    global current_settings
    current_settings = base_settings.copy()
    check_file(directories.settings)
    with open(directories.settings, mode = "r", encoding = "utf-8") as file:
        data = file.read()
    if not data:
        return
    setting_category = None
    settings = data.split("\n")
    for setting in settings:
        setting = setting.split("#")[0].replace("\t", "").strip(" ")
        if not setting:
            continue
        if setting[0] == "[" and setting[-1] == "]":
            setting_category = setting[1:-1]
        elif setting_category:
            setting, value = [part.strip(" ") for part in setting.split("=")]
            if type(current_settings[setting_category][setting]) == bool:
                value = string_bool_meaning(value)
            if setting_category:
                current_settings[setting_category][setting] = value
            elif type(current_settings[setting]) != dict:
                current_settings[setting] = value

def import_ip_list(directory):
    ip_list = ip_lists[directory.key]
    ip_list.clear()
    check_file(directory)
    with open(directory, mode = "r", encoding = "utf-8") as file:
        data = file.read()
    if not data:
        return
    ip_addresses = data.split("\n")
    for i, ip_address in enumerate(ip_addresses, start = 1):
        ip_address = ip_address.split("#")[0].strip(" ").strip("\t")
        if not ip_address:
            continue
        try:
            ipaddress.IPv4Network(ip_address, strict = False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exception:
            logging_print("While importing \"{}\", the ip address at line {} gave an error: ({}).".format(directory.basename(), i, exception))
            continue
        ip_list.add(ip_address)

class Event_Handler(FileSystemEventHandler):
    def __init__(self):
        FileSystemEventHandler.__init__(self)
        self.ignore = False
    def on_modified(self, event):
        self.ignore = not self.ignore
        if self.ignore:
            return
        for directory in [directories.allowlist, directories.blacklist]:
            if event.src_path == directory.string():
                import_ip_list(directory)
                rule_updater.update = True
                break

class Rule_Updater(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

        self.update = False
        self.force = False
        self.ip_list = set()

    def run(self):
        while True:
            if not self.update:
                time.sleep(1); continue
            self.update = False
            temp_ip_list = ip_lists["allowlist"].difference(ip_lists["blacklist"])
            if not self.force and self.ip_list == temp_ip_list:
                time.sleep(1); continue
            self.force = False
            print("Updating Ip list rules...")
            self.ip_list = temp_ip_list
##            print(self.ip_list)
            
            print("Done!")

try:
    import_settings()
    
    import_ip_list(directories.allowlist)
    import_ip_list(directories.blacklist)

    observer = Observer()
    observer.schedule(Event_Handler(), directories.data.string())
    observer.start()

    rule_updater = Rule_Updater()
    rule_updater.update = True
    rule_updater.force = True
    rule_updater.start()

except:
    logging_print(traceback.format_exc())
