from modules.header_directories import Directory_Manager

directories = Directory_Manager(
    data = [".", "data"],
    logs = [".data", "logs"],
    log = [".logs", "log_{strftime}.txt"],
    configs = [".data", "configs.txt"],
    commands = [".data", "commands.txt"],
    allowlist = [".data", "allowlist.txt"],
    blacklist = [".data", "blacklist.txt"],
    currentlist = [".data", "currentlist.txt"],
    ip_uids = [".data", "ip uids.txt"],
    dumpcap = [".data", "dumpcap"],
    pcap = [".dumpcap", "{filename}.pcap"],
)
