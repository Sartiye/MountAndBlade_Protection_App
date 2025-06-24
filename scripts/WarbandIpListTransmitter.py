import socket
import traceback
import threading
import time

def serialize(*args):
    return ("{}|" * len(args)).format(*args)

def send_message_warband(client, *message):
    text = "HTTP/1.1 200 OK\r\nContent-Lenght: {}\r\n\r\n{}\r\n".format(128, serialize(*message))
    client.send(text.encode())

protection_addr = ("0.0.0.0", 7010)
warband_addr = ("127.0.0.2", 80)
messages = list()
messages_lock = threading.Lock()

##while True:
##    try:
##        server = socket.socket()
##        server.connect(protection_addr)
##        server.send("clear%currentlist".encode())
##        server.close()
##        print("Cleared currentlist of server.")
##        break
##    except:
##        print("Couldn't connect to protection server:", traceback.format_exc())

def message_sender():
    while True:
        if not messages:
            time.sleep(1)
            continue
        with messages_lock:
            cur_messages = messages.copy()
            messages.clear()
        print("Sending the current message: {}".format([message.split("%") for message in cur_messages]))
        try:
            while True:
                server = socket.socket()
                server.connect(protection_addr)
                server.send("%".join(cur_messages).encode())
                server.close()
                break
        except:
          print("Couldn't transfer the message to protection server:", traceback.format_exc())
    
def warband_listener():
    while True:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(warband_addr)
            server.listen(5)
            print("Listening warband.")

            while True:
                client, addr = server.accept()
                message = client.recv(1024).decode()
                send_message_warband(client, "0")
                client.close()
                message = message.split(" ")[1][1:].split("%3C")
                print("Received new ip list message: {}".format(message))
                with messages_lock:
                    messages.append("%".join(message))
        except:
          print("Something went wrong on warband_listener:", traceback.format_exc())
    
threading.Thread(target = message_sender).start()
threading.Thread(target = warband_listener).start()
      
