import sys, os
import traceback
import threading
import datetime
import pyshark
import ipaddress
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from module_directories import directories

class EventHandler(FileSystemEventHandler):
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

allowlist = set()
blacklist = set()
ip_lists = {"allowlist": allowlist, "blacklist": blacklist}

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

try:
    import_ip_list(directories.allowlist)
    import_ip_list(directories.blacklist)

    observer = Observer()
    observer.schedule(EventHandler(), directories.data.string())
    observer.start()
except:
    logging_print(traceback.format_exc())
