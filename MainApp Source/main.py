import sys, os
import traceback
import threading
import time
import random
import string as string_lib
import datetime
import socket
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

def import_error(directory, object_name, line, exception):
    logging_print("While importing \"{}\", the {} at line {} gave an error: ({}).".format(directory.basename(), object_name, line, exception))

def get_random_string(length):
    random_list = []
    for i in range(length):
        random_list.append(random.choice(string_lib.ascii_letters + string_lib.digits))
    return "".join(random_list)

base_configs = {
    "gcloud" : {
        "active" : False,
    },
    "advanced firewall" : {
        "active" : False,
    },
    "pyshark" : {
        "active" : False,
        "port" : 25556,
        "host" : -1,
    },
    "dumpcap" : {
        "active" : False,
    },
    "IP UIDs" : {
        "clean start" : False,
        "randomize" : True,
    },
    "cloudflare" : {
        "active" : True,
        "hostname" : "warbandmain.taleworlds.com",
        "port" : 80,
    },
    "dumpcap" : {
        "active" : False,
        "filename" : "dumpcap",
    },
}
base_commands = {
    "cloudflare" : {
        "ping" : "",
        "confirm ping" : "",
    }
}

ip_lists = {"allowlist": set(), "blacklist": set()}
configs = base_configs.copy()
commands = base_commands.copy()

def import_configs(directory):
    global configs
    configs = base_configs.copy()
    check_file(directory)
    with open(directory, mode = "r", encoding = "utf-8") as file:
        data = file.read()
    if not data:
        return
    category = None
    raw_configs = data.split("\n")
    for i, config in enumerate(raw_configs, start = 1):
        config = config.split("#")[0].replace("\t", "").strip(" ")
        if not config:
            continue
        if config[0] == "[" and config[-1] == "]":
            category = config[1:-1]
            if not category in configs:
                import_error(directory, "category", i, "The category does not exist.")
                category = None
        elif category:
            config, value = [part.strip(" ") for part in config.split("=")]
            if not config in configs[category]:
                import_error(directory, "config", i, "The config does not exist.")
            if type(configs[category][config]) == bool:
                value = string_bool_meaning(value)
            elif type(configs[category][config]) == int:
                try:
                    value = int(value)
                except exception:
                    import_error(directory, "config", i, exception)
            configs[category][config] = value
        else:
            import_error(directory, "config", i, "A category must be defined.")

def import_commands(directory):
    global commands
    commands = base_commands.copy()
    check_file(directory)
    with open(directory, mode = "r", encoding = "utf-8") as file:
        data = file.read()
    if not data:
        return
    command_tuple = None
    raw_commands = data.split("\n")
    for i, line in enumerate(raw_commands, start = 1):
        line = line.split("#")[0].replace("\t", "").strip(" ")
        if not line:
            continue
        if line[0] == "[" and line[-1] == "]":
            line = line[1:-1]
            if line in ["", "\\"]:
                command_tuple = None
                continue
            parts = line.split(".")
            if not len(parts) == 2:
                import_error(directory, "command", i, "The command defined incorrectly. Syntax: \"[<category>.<command>]\"")
                command_tuple = None
                continue
            category, command = parts
            if not category in commands:
                import_error(directory, "category", i, "The category does not exist.")
                command_tuple = None
                continue
            if not command in commands[category]:
                import_error(directory, "command", i, "The command does not exist.")
                command_tuple = None
                continue
            command_tuple = (category, command)
        elif command_tuple != None:
            category, command = command_tuple
            line = line.replace("\\r", "\r").replace("\\n", "\n")
            commands[category][command] += line
        else:
            import_error(directory, "command", i, "A command must be defined.")

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
            import_error(directory, "ip address", i, exception)
            continue
        ip_list.add(ip_address)

class IP_UID_Manager():
    def __init__(self, directory):
        self.directory = directory
        self.ip_uids = dict()
        self.uids = set()

    def import_directory(self):
        self.ip_uids.clear()
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
                import_error(directory, "ip address", i, exception)
                continue
            self.ip_uids[ip_address] = unique_id
            self.uids.add(unique_id)

    def generate_new_unique_id(self):
        while True:
            unique_id = get_random_string(6)
            if unique_id in self.uids:
                continue
            self.uids.add(unique_id)
            return unique_id

    def get_unique_id(self, ip_address):
        if ip_address in self.ip_uids:
            return self.ip_uids[ip_address]
        self.ip_uids[ip_address] = self.generate_new_unique_id()
        return self.ip_uids[ip_address]

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

def cloudflare_communicator():
    can_run = True
    for key, command in commands["cloudflare"].items():
        if not command:
            logging_print("Warning! You need the command [cloudflare.{}] defined in order to activate cloudflare.".format(key))
            can_run = False
    while can_run:
        try:
            host = socket.gethostbyname(configs["cloudflare"]["hostname"])
            if configs["pyshark"]["host"] != -1:
                os.system("route add {} {}".format(host, configs["pyshark"]["host"]))
            server = socket.create_connection((host, configs["cloudflare"]["port"]))
            server.send(
                commands["cloudflare"]["ping"].format(
                    port = configs["pyshark"]["port"],
                    hostname = configs["cloudflare"]["hostname"]
                ).encode()
            )
            response = server.recv(1024).decode()
            code = response.split("\r\n\r\n")[1]
            server.send(
                commands["cloudflare"]["confirm ping"].format(
                    port = configs["pyshark"]["port"],
                    code = code,
                    hostname = configs["cloudflare"]["hostname"],
                ).encode()
            )
            response = server.recv(1024).decode()
            server.close()
            if configs["pyshark"]["host"] != -1:
                os.system("route delete {}".format(host))
            logging_print("Pinged {} ({})".format(configs["cloudflare"]["hostname"], host))
            time.sleep(300)
        except:
            logging_print("cloudflare communicator:", traceback.format_exc())
            time.sleep(10)

try:
    import_configs(directories.configs)
    import_commands(directories.commands)
    
    import_ip_list(directories.allowlist)
    import_ip_list(directories.blacklist)

    time.sleep(1)

    ip_uid_manager = IP_UID_Manager(directories.ip_uids)
    ip_uid_manager.import_directory()

    observer = Observer()
    observer.schedule(Event_Handler(), directories.data.string())
    observer.start()

    rule_updater = Rule_Updater()
    rule_updater.update = True
    rule_updater.force = True
    rule_updater.start()

    time.sleep(1)
    
    if configs["cloudflare"]["active"]:
        threading.Thread(target = cloudflare_communicator).start()
except:
    logging_print(traceback.format_exc())
    sys.exit()
