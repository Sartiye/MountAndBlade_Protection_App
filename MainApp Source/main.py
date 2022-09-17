import sys, os
import traceback
import threading
import time
import random
import string as string_lib
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

def import_errror(directory, object_name, line, exception):
    logging_print("While importing \"{}\", the {} at line {} gave an error: ({}).".format(directory.basename(), object_name, line, exception))

def get_random_string(length):
    random_list = []
    for i in range(length):
        random_list.append(random.choice(string_lib.ascii_letters + string_lib.digits))
    return "".join(random_list)

base_settings = {
    "google cloud" : {
        "active" : False,
    },
    "advanced firewall" : {
        "active" : False,
    },
    "pyshark" : {
        "active" : False,
    },
    "dumpcap" : {
        "active" : False,
    },
    "ip list unique ids" : {
        "clean start" : False,
        "randomize" : True,
    },
}

ip_lists = {"allowlist": set(), "blacklist": set()}
current_settings = base_settings.copy()

def import_settings(directory):
    global current_settings
    current_settings = base_settings.copy()
    check_file(directory)
    with open(directory, mode = "r", encoding = "utf-8") as file:
        data = file.read()
    if not data:
        return
    category = None
    settings = data.split("\n")
    for i, setting in enumerate(settings, start = 1):
        setting = setting.split("#")[0].replace("\t", "").strip(" ")
        if not setting:
            continue
        if setting[0] == "[" and setting[-1] == "]":
            category = setting[1:-1]
            if not category in current_settings:
                import_errror(directory, "category", i, "That category does not exist.")
                category = None
        elif category:
            setting, value = [part.strip(" ") for part in setting.split("=")]
            if not setting in current_settings[category]:
                import_errror(directory, "setting", i, "That setting does not exist.")
            if type(current_settings[category][setting]) == bool:
                value = string_bool_meaning(value)
            elif type(current_settings[category][setting]) == int:
                try:
                    value = int(value)
                except exception:
                    import_errror(directory, "setting", i, exception)
            current_settings[category][setting] = value
        else:
            import_errror(directory, "setting", i, "A category must be defined.")

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
            import_errror(directory, "ip address", i, exception)
            continue
        ip_list.add(ip_address)

class IP_Address_UID_Manager():
    def __init__(self, directory):
        self.directory = directory
        self.ip_address_unique_ids = dict()
        self.unique_ids = set()

    def import_directory(self):
        self.ip_address_unique_ids.clear()
        check_file(self.directory)
        with open(self.directory, mode = "r", encoding = "utf-8") as file:
            data = file.read()
        if not data:
            return
        lines = data.split("\n")
        for i, line in enumerate(lines, start = 1):
            line = line.split("#")[0].replace("\t", "").replace(" ", "").lower()
            if not line:
                continue
            ip_address, unique_id = line.split(":")
            try:
                ipaddress.IPv4Network(ip_address, strict = False)
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exception:
                import_errror(directory, "ip address", i, exception)
                continue
            self.ip_address_unique_ids[ip_address] = unique_id
            self.unique_ids.add(unique_id)

    def generate_new_unique_id(self):
        while True:
            unique_id = get_random_string(6)
            if unique_id in self.unique_ids:
                continue
            self.unique_ids.add(unique_id)
            return unique_id

    def get_unique_id(self, ip_address):
        if ip_address in self.ip_address_unique_ids:
            return self.ip_address_unique_ids[ip_address]
        self.ip_address_unique_ids[ip_address] = self.generate_new_unique_id()
        return self.ip_address_unique_ids[ip_address]

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
            new_ip_list = ip_lists["allowlist"].difference(ip_lists["blacklist"])
            if not self.force and self.ip_list == new_ip_list:
                time.sleep(1); continue
            self.force = False
            print("Updating IP List rules...")
            ip_list_to_remove = self.ip_list.difference(new_ip_list)
            self.ip_list = new_ip_list
            
            print("Done!")

try:
    import_settings(directories.settings)
    
    import_ip_list(directories.allowlist)
    import_ip_list(directories.blacklist)

    ip_address_uid_manager = IP_Address_UID_Manager(directories.ip_address_uids)
    ip_address_uid_manager.import_directory()

    observer = Observer()
    observer.schedule(Event_Handler(), directories.data.string())
    observer.start()

    rule_updater = Rule_Updater()
    rule_updater.update = True
    rule_updater.force = True
    rule_updater.start()

except:
    logging_print(traceback.format_exc())
    sys.exit()
