from header_directories import *

directories = Directory_Manager(
    data = [".", "Data"],
    logs = [".data", "logs.txt"],
    settings = [".data", "settings.txt"],
    rule_defines = [".data", "rule defines.txt"],
    allowlist = [".data", "allowlist.txt"],
    blacklist = [".data", "blacklist.txt"],
    ip_address_uids = [".data", "ip address uids.txt"],
)
