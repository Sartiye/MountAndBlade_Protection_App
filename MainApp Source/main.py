import sys
import os
import traceback
import msvcrt
import time
import random
import string as string_lib
import socket
import threading
import subprocess
import datetime
import pyshark
import ipaddress
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from module_directories import directories
import admin

if not admin.isUserAdmin():
    admin.runAsAdmin(wait = False)
    sys.exit(0)

eval_string = ""
file_call = False

def print_(*string, sep = " ", end = "\n", flush = False):
    if eval_string:
        print("\r" + " " * len(eval_string) + "\r", end = ""),
    print("[{}]".format(datetime.datetime.now().strftime("%H:%M:%S")), *string, sep = sep, end = end, flush = flush)
    directories.log.format(strftime = datetime.datetime.now().strftime("%Y_%m_%d"))
    check_file(directories.log)
    with open(directories.log, "a", encoding="utf-8") as file:
        old_stdout = sys.stdout
        sys.stdout = file
        print("[{}]".format(datetime.datetime.now().strftime("%H:%M:%S")), *string, sep = sep, end = end, flush = flush)
        sys.stdout = old_stdout
    if eval_string:
        print(eval_string, end = "", flush = True),
        
def check_file(directory):
    try:
        with open(directory, mode = "x", encoding = "utf-8"):
            print_("Created the file: \"{}\".".format(directory.basename()))
    except FileExistsError:
        pass

def clean_file(directory):
    with open(directory, mode = "w", encoding = "utf-8"):
        print_("Cleaned the file: \"{}\".".format(directory.basename()))

def append_new_line(directory, string):
    with open(directory, "r+") as file:
        data = file.read()
        file.write(("" if not data or data[-1] == "\n" else "\n") + string)

def string_bool_meaning(string):
    true_strings = ["1", "true", "yes", "+"]
    return string.lower() in true_strings

def import_error(directory, object_name, line, exception):
    print_("While importing \"{}\", the {} at line {} gave an error: ({}).".format(directory.basename(), object_name, line, exception))

def check_commands(category, not_necessary_commands):
    defined = True
    for key, command in commands[category].items():
        if not command and not key in not_necessary_commands:
            print_("Warning! You need the command [{0}.{1}] defined in order to activate {0}.".format(category, key))
            defined = False
    return defined

def get_random_string(length):
    random_list = []
    for i in range(length):
        random_list.append(random.choice(string_lib.ascii_lowercase + string_lib.digits))
    return "".join(random_list)

base_host = socket.gethostbyname(socket.gethostname())
base_configs = {
    "warband" : {
        "interface" : "Ethernet",
        "host" : base_host,
        "port" : 7240,
    },
    "IP UIDs" : {
        "clean start" : False,
        "randomize" : False,
        "always list" : False,
    },
    "google cloud" : {
        "active" : False,
        "project" : "",
        "header" : "warband",
        "priority" : 1000,
        "network" : "",
        "group rules" : False,
    },
    "advanced firewall" : {
        "active" : False,
        "header" : "warband",
    },
    "pyshark" : {
        "active" : False,
        "interface" : "Ethernet",
        "filter" : "host {host} && port {port}",
        "host" : base_host,
        "port" : 25161,
    },
    "cloudflare" : {
        "active" : False,
        "hostname" : "warbandmain.taleworlds.com",
        "port" : 80,
        "gateway" : "",
    },
    "dumpcap" : {
        "active" : False,
        "application" : "C:\Program Files\Wireshark\dumpcap",
        "filesize" : 100000,
        "printname" : "stdout",
        "filename" : "mycap",
        "filter" : "host {host} && port {port}",
        "show stdout" : False,
    },
    "eval" : {
        "active" : False,
        "header" : "Input: ",
    },
}
base_commands = {
    "google cloud" : {
        "list" : "",
        "create" : "",
        "delete" : "",
    },
    "advanced firewall" : {
        "list" : "",
        "create" : "",
        "delete" : "",
    },
    "cloudflare" : {
        "ping" : "",
        "confirm ping" : "",
    },
    "dumpcap" : {
        "command" : "",
    },
}

ip_lists = {"allowlist": set(), "blacklist": set()}
ip_lists_lock = threading.Lock()
configs = base_configs.copy()
commands = base_commands.copy()
rule_list = list()

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
    with ip_lists_lock:
        ip_list = ip_lists[directory.key]
        ip_list.clear()
        check_file(directory)
        with open(directory, mode = "r", encoding = "utf-8") as file:
            data = file.read()
        if not data:
            return
        if configs["IP UIDs"]["clean start"]:
            clean_file(directory)
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
        self.uid_count = 1

    def import_directory(self):
        self.ip_uids.clear()
        check_file(self.directory)
        with open(self.directory, mode = "r", encoding = "utf-8") as file:
            data = file.read()
        if not data:
            return
        if configs["IP UIDs"]["clean start"]:
            clean_file(self.directory)
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
        for i in range(len(self.uids)):
            if not str(self.uid_count) in self.uids:
                break
            self.uid_count += 1
    
    def generate_new_unique_id(self):
        while True:
            if configs["IP UIDs"]["randomize"]:
                unique_id = get_random_string(6)
            else:
                unique_id = str(self.uid_count)
            if unique_id in self.uids:
                self.uid_count += 1
                continue
            self.uids.add(unique_id)
            return unique_id

    def get_unique_id(self, ip_address):
        if ip_address in self.ip_uids:
            return self.ip_uids[ip_address]
        unique_id = self.generate_new_unique_id()
        self.ip_uids[ip_address] = unique_id
        append_new_line(directories.ip_uids, "{} : {}".format(ip_address, unique_id))
        return unique_id

#
class Event_Handler(FileSystemEventHandler):
    def __init__(self):
        FileSystemEventHandler.__init__(self)
        
    def on_modified(self, event):
        global file_call
        
        for directory in [directories.allowlist, directories.blacklist]:
            if event.src_path == directory.string():
                import_ip_list(directory)
                if not file_call:
                    print_("Data change detected on file: {}".format(directory.basename()))
                file_call = False
                rule_updater.update = True
                break


class Rule():
    def __init__(self):
        self.defined = False

    def list(self):
        return list()

    def create(self, unique_id, ip_address):
        print_("Created rule with unique_id: {}, ip address: {}".format(unique_id, ip_address))

    def delete(self, unique_id):
        print_("Deleted rule with unique_id: {}".format(unique_id))

    def refresh(self, ip_list):
        pass


class Google_Cloud(Rule):
    def __init__(self):
        self.defined = True
        if not check_commands("google cloud", []):
            self.defined = False
        for config in ["project", "network"]:
            if not configs["google cloud"][config]:
                print_("Warning! You need the config \"{}\" defined in order to activate google cloud.".format(config))
                self.defined = False
        self.current_header = get_random_string(5)
        self.current_rule_headers = []
        self.old_rule_headers = []

    def list(self):
        kwargs = {
            "project" : configs["google cloud"]["project"],
            "header" : configs["google cloud"]["header"],
        }
        rules = [str(rule).split(" ")[0] for rule in subprocess.check_output(
            commands["google cloud"]["list"].format(**kwargs),
            shell = True,
            stderr = subprocess.PIPE,
        ).decode().split("\n")][1:-1]
        rules = [rule.split("-")[1] for rule in rules]
        return rules

    def create(self, unique_id, ip_address, refresh = False):
        if (not configs["google cloud"]["group rules"] or refresh):
            kwargs = {
                "project" : configs["google cloud"]["project"],
                "header" : configs["google cloud"]["header"],
                "unique_id" : unique_id,
                "priority" : configs["google cloud"]["priority"],
                "network" : configs["google cloud"]["network"],
                "port" : configs["warband"]["port"],
                "ip_address" : ip_address,
            }
            subprocess.check_call(
                commands["google cloud"]["create"].format(**kwargs),
                shell = True,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
            )
            print_("Created rule with ip address: {}, unique id: {}".format(ip_address, unique_id))

    def delete(self, unique_id, refresh = False):
        if (not configs["google cloud"]["group rules"] or refresh):
            kwargs = {
                "project" : configs["google cloud"]["project"],
                "header" : configs["google cloud"]["header"],
                "unique_id" : unique_id,
            }
            subprocess.Popen(
                commands["google cloud"]["delete"].format(**kwargs),
                shell = True,
                stdin = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
            ).communicate("Y".encode())
            print_("Deleted rule with unique_id: {}".format(unique_id))

    def split_ip_list(self, ip_adresses):
        ip_lists = []
        while len(ip_adresses) > 256:
            ip_lists.append(ip_adresses[:256])
            ip_adresses = ip_adresses[256:]
        if ip_adresses:
            ip_lists.append(ip_adresses)
        return ip_lists

    def refresh(self, ip_list):
        if (configs["google cloud"]["group rules"]):
            current_header = get_random_string(5)
            ip_lists = self.split_ip_list(ip_list)
            del self.old_rule_headers
            self.old_rule_headers = self.current_rule_headers.copy()
            self.current_rule_headers.clear()
            for i, ip_list in enumerate(ip_lists):
                header = current_header + "-" + str(i)
                self.create(header, ",".join(ip_list), refresh = True)
                self.current_rule_headers.append(header)
            for header in self.old_rule_headers:
                self.delete(header, refresh = True)


class Advanced_Firewall(Rule):
    def __init__(self):
        self.defined = True
        if not check_commands("advanced firewall", []):
            self.defined = False

    def list(self):
        kwargs = {
            "port" : configs["warband"]["port"],
        }
        try:
            rules = [rule.strip().split("-")[1] for rule in subprocess.check_output(
                commands["advanced firewall"]["list"].format(**kwargs),
                shell = True,
                stderr = subprocess.PIPE,
            ).decode().split("\r\n")[:-1]]
        except subprocess.CalledProcessError:
            return []
        return rules

    def create(self, unique_id, ip_address):
        kwargs = {
            "header" : configs["advanced firewall"]["header"],
            "unique_id" : unique_id,
            "port" : configs["warband"]["port"],
            "ip_address" : ip_address,
        }
        subprocess.check_call(
            commands["advanced firewall"]["create"].format(**kwargs),
            shell = True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        print_("Created rule with ip address: {}, unique id: {}".format(ip_address, unique_id))

    def delete(self, unique_id):
        kwargs = {
            "header" : configs["advanced firewall"]["header"],
            "unique_id" : unique_id,
        }
        subprocess.check_call(
            commands["advanced firewall"]["delete"].format(**kwargs),
            shell = True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        print_("Deleted rule with unique_id: {}".format(unique_id))


class Rule_Updater(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

        self.update = False
        self.force = False
        self.ip_list = set()
        self.unique_ids = set()

    def list_rules(self):
        self.unique_ids.clear()
        self.unique_ids.update(rule_list[0].list())
        
    def create_rule(self, unique_id, ip_address):
        for rule in rule_list:
            rule.create(unique_id, ip_address)
        self.unique_ids.add(unique_id)
        
    def delete_rule(self, unique_id):
        for rule in rule_list:
            rule.delete(unique_id)
        self.unique_ids.remove(unique_id)

    def refresh_rules(self, ip_list):
        for rule in rule_list:
            rule.refresh(ip_list)

    def run(self):
        while True:
            try:
                if not self.update:
                    time.sleep(1); continue
                self.update = False

                with ip_lists_lock:
                    new_ip_list = ip_lists["allowlist"].difference(ip_lists["blacklist"])
                
                if not self.force and self.ip_list == new_ip_list:
                    time.sleep(1); continue
                print_("Updating IP List rules{}...".format(" (force: True)" if self.force else ""))
                
                if configs["IP UIDs"]["always list"] or self.force:
                    self.list_rules()
                self.force = False
                
                del self.ip_list
                self.ip_list = new_ip_list
                new_unique_ids = set(ip_uid_manager.get_unique_id(ip_address) for ip_address in self.ip_list)
                old_unique_ids = self.unique_ids.copy()
                difference = old_unique_ids.difference(new_unique_ids)
                for unique_id in difference:
                    self.delete_rule(unique_id)
                for ip_address in self.ip_list:
                    unique_id = ip_uid_manager.get_unique_id(ip_address)
                    if not unique_id in self.unique_ids:
                        self.create_rule(unique_id, ip_address)
                configs["IP UIDs"]["clean start"] = False
                self.refresh_rules(self.ip_list)
                print_("Done!")
            except:
                print_("rule updater:", traceback.format_exc())
                self.update = True
                self.force = True
                time.sleep(10)


def pyshark_listener():
    global file_call
    try:
        while configs["IP UIDs"]["clean start"]:
            time.sleep(1)
        capture = pyshark.LiveCapture(
            configs["pyshark"]["interface"],
            bpf_filter = configs["pyshark"]["filter"].format(
                host = configs["pyshark"]["host"],
                port = configs["pyshark"]["port"]
            ),
        )
        print_(
            "Started listening interface: \"{}\", host: {}, port: {}".format(
                configs["pyshark"]["interface"],
                configs["pyshark"]["host"],
                configs["pyshark"]["port"],
            )
        )
        for packet in capture.sniff_continuously():
            source_ip = packet.ip.src
            if source_ip == configs["pyshark"]["host"]: continue
            if not source_ip in ip_lists["allowlist"]:
                ip_lists["allowlist"].add(source_ip)
                file_call = True
                append_new_line(directories.allowlist, source_ip)
                unique_id = ip_uid_manager.get_unique_id(source_ip)
                print_("Verified new ip address: {}, unique_id: {}".format(source_ip, unique_id))
    except:
        print_("pyshark listener:", traceback.format_exc())

def cloudflare_communicator():
    if not check_commands("cloudflare", []):
        return
    while True:
        try:
            route = bool(configs["cloudflare"]["gateway"])
            host = socket.gethostbyname(configs["cloudflare"]["hostname"])
            if route:
                subprocess.check_call(
                    "route add {} {}".format(host, configs["cloudflare"]["gateway"]),
                    shell = True,
                    stdout = subprocess.PIPE,
                )
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
            print_(
                "Pinged host: {} ({}), port: {}, gateway: {}".format(
                    configs["cloudflare"]["hostname"],
                    host,
                    configs["pyshark"]["port"],
                    configs["cloudflare"]["gateway"] if route else "On-link",
                )
            )
            if route:
                subprocess.check_call(
                    "route delete {}".format(host),
                    shell = True,
                    stdout = subprocess.PIPE,
                )
            time.sleep(300)
        except:
            print_("cloudflare communicator:", traceback.format_exc())
            time.sleep(10)

def dumpcap_logger():
    if not check_commands("dumpcap", []):
        return
    try:
        while True:
            kwargs = {
                "application" : configs["dumpcap"]["application"],
                "filesize" : configs["dumpcap"]["filesize"],
                "printname" : configs["dumpcap"]["printname"],
                "write" : directories.pcap.format(filename = configs["dumpcap"]["filename"]),
                "interface" : configs["warband"]["interface"],
                "filter" : configs["dumpcap"]["filter"].format(host = configs["warband"]["host"], port = configs["warband"]["port"]),
            }
            parameters = [parameter.format(**kwargs) for parameter in commands["dumpcap"]["command"].split(" ")]
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.Popen(
                parameters,
                startupinfo = startupinfo,
                stdout = None if configs["dumpcap"]["show stdout"] else subprocess.PIPE,
                stderr = subprocess.PIPE,
            ).wait()
    except:
        print_("dumpcap logger:", traceback.format_exc())

def eval_tool():
    def append_eval_string(string):
        global eval_string
        
        eval_string += string
        print(string, end = "", flush = True)
        
    def clear_eval_string():
        global eval_string

        print("\r" + " " * len(eval_string) + "\r", end = "")
        eval_string = ""
        append_eval_string(configs["eval"]["header"])

    def pop_eval_string():
        global eval_string

        if len(eval_string) > len(configs["eval"]["header"]):
            print("\r" + " " * len(eval_string) + "\r", end = "")
            eval_string = eval_string[:-1]
            print(eval_string, end = "", flush = True)

    def clear_screen():
        os.system("cls")
        clear_eval_string()

    def eval_eval_string():
        global eval_string

        eval_command = eval_string[len(configs["eval"]["header"]):]
        if eval_command in ["clear", "cls"]:
            clear_screen()
            return
        print_(eval_string)
        clear_eval_string()
        try:
            response = eval(eval_command)
        except SyntaxError:
            response = exec(eval_command)
        if response:
            print_("Response: {}".format(response))
        else:
            print_("Command executed.")

    while True:
        try:
            clear_eval_string()
            print_("Started eval tool.")
            while True:
                if msvcrt.kbhit():
                    char = msvcrt.getwch()
                    if char == "\r":
                        eval_eval_string()
                    elif char == "\b":
                        pop_eval_string()
                    elif char == chr(27):
                        clear_screen()
                    else:
                        append_eval_string(char)
        except:
            print_("eval tool:", traceback.format_exc())

            
try:
    print_("Loading...")
    import_configs(directories.configs)
    import_commands(directories.commands)

    if configs["IP UIDs"]["clean start"]:
        print_("Initaiting a clean start.")
    
    import_ip_list(directories.allowlist)
    import_ip_list(directories.blacklist)

    time.sleep(1)

    ip_uid_manager = IP_UID_Manager(directories.ip_uids)
    ip_uid_manager.import_directory()

    if configs["advanced firewall"]["active"]:
        rule = Advanced_Firewall()
        if rule.defined:
            rule_list.append(rule)

    if configs["google cloud"]["active"]:
        rule = Google_Cloud()
        if rule.defined:
            rule_list.append(rule)

    if configs["pyshark"]["active"]:
        threading.Thread(target = pyshark_listener).start()
    
    if configs["cloudflare"]["active"]:
        threading.Thread(target = cloudflare_communicator).start()
        time.sleep(1)

    if configs["dumpcap"]["active"]:
        threading.Thread(target = dumpcap_logger).start()
        time.sleep(1)

    rule_updater = Rule_Updater()
    rule_updater.update = True
    rule_updater.force = True
    rule_updater.start()

    observer = Observer()
    observer.schedule(Event_Handler(), directories.data.string())
    observer.start()

    time.sleep(1)

    if configs["eval"]["active"]:
        time.sleep(1)
        threading.Thread(target = eval_tool).start()
except:
    print_(traceback.format_exc())
    input()
