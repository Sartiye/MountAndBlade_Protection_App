from header_directories import *

directories = Directory_Manager(
    data = [".", "Data"],
    logs = [".data", "Logs"],
    log = [".logs", "log_{strftime}.txt"],
    configs = [".data", "configs.txt"],
    commands = [".data", "commands.txt"],
    allowlist = [".data", "allowlist.txt"],
    blacklist = [".data", "blacklist.txt"],
    currentlist = [".data", "currentlist.txt"],
    ip_uids = [".data", "ip uids.txt"],
    dumpcap = [".data", "Dumpcap"],
    pcap = [".dumpcap", "{filename}.pcap"],
)
