from header_directories import *

directories = Directory_Manager(
    data = [".", "Data"],
    logs = [".data", "logs.txt"],
    configs = [".data", "configs.txt"],
    commands = [".data", "commands.txt"],
    allowlist = [".data", "allowlist.txt"],
    blacklist = [".data", "blacklist.txt"],
    ip_uids = [".data", "ip uids.txt"],
)
