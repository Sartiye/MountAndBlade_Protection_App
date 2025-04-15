import socket
import struct

def get_knock_port(ip_address: str, base_port: int = 50000, range_size: int = 10000):
    # Convert IP to 32-bit unsigned int
    packed_ip = socket.inet_aton(ip_address)             # e.g., b'\xcb\x00q-'
    ip_int = struct.unpack("!I", packed_ip)[0]            # Unsigned int in network byte order

    # Apply XOR salt (must match C# version: 0xA5A5A5A5)
    salted = ip_int ^ 0xA5A5A5A5

    # Generate port in the desired range
    knock_port = base_port + (salted % range_size)
    return knock_port

# ✅ Test
ip = socket.gethostbyname(socket.gethostname())
port = get_knock_port(ip)
print(f"Knock port for {ip}: {port}")
