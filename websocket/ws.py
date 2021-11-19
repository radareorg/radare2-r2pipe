import signal, sys
from SimpleWebSocketServer import WebSocket, SimpleWebSocketServer
import r2pipe

 
PORTNUM = 5678
 
# Websocket class to echo received data
class Echo(WebSocket):
 
    def handleMessage(self):
        res = self.r2.cmd(self.data)
        print("Run '%s'" % self.data)
        self.sendMessage(res)
 
    def handleConnected(self):
        self.r2 = r2pipe.open("--")
        print("Connected")
 
    def handleClose(self):
        self.r2.quit()
        self.r2 = None
        print("Disconnected")
 
# Handle ctrl-C: close server
def close_server(signal, frame):
    server.close()
    sys.exit()
 
if __name__ == "__main__":
    print("Websocket server on port %s" % PORTNUM)
    server = SimpleWebSocketServer('', PORTNUM, Echo)
    signal.signal(signal.SIGINT, close_server)
    server.serveforever()
