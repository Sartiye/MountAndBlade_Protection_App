import socket
import time
import os
import traceback

port = 25556

ping_message = "\
GET /handlerservers.ashx?type=ping&keys&port={port}&hidden=false HTTP/1.1\r\n\
Connection: Keep-Alive\r\n\
User-Agent: Mount Blade HTTP\r\n\
Host: warbandmain.taleworlds.com\r\n\
\r\n\
"

confirm_ping_message = "\
GET /handlerservers.ashx?type=confirmping&port={port}&rand={code}&hidden=false HTTP/1.1\r\n\
Connection: Keep-Alive\r\n\
User-Agent: Mount Blade HTTP\r\n\
Host: warbandmain.taleworlds.com\r\n\
\r\n\
"
while True:
    try:
        taleworlds = socket.gethostbyname("warbandmain.taleworlds.com")
##        os.system("route add {} 10.1.0.1".format(taleworlds))
        
        server = socket.create_connection((taleworlds, 80))
        server.send(ping_message.format(port=port).encode())
        response = server.recv(1024).decode()
        code = response.split("\r\n\r\n")[1]

        server.send(confirm_ping_message.format(port = port, code = code).encode())

        response = server.recv(1024).decode()
        print(response.split("\r\n\r\n")[1])

        server.close()
        
##        os.system("route delete {}".format(taleworlds))
        
        time.sleep(300)
    except KeyboardInterrupt:
        break
    except:
        input(traceback.format_exc())


