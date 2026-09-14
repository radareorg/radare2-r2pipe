import signal, sys, os, hmac
from SimpleWebSocketServer import WebSocket, SimpleWebSocketServer
import r2pipe

 
PORTNUM = 5678
# Shared secret required before any command is executed. Must be set in the
# environment; the server refuses to start without it (fail closed).
AUTH_TOKEN = os.environ.get("R2PIPE_WS_TOKEN")
 
# Websocket class to echo received data
class Echo(WebSocket):
 
    def handleMessage(self):
        if not getattr(self, "authenticated", False):
            if hmac.compare_digest(str(self.data), AUTH_TOKEN):
                self.authenticated = True
                self.sendMessage("auth ok")
            else:
                self.sendMessage("auth required")
                self.close()
            return
        res = self.r2.cmd(self.data)
        print("Run '%s'" % self.data)
        self.sendMessage(res)
 
    def handleConnected(self):
        self.authenticated = False
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
    if not AUTH_TOKEN:
        sys.exit("R2PIPE_WS_TOKEN env var must be set to a secret token before starting the server")
    print("Websocket server on port %s" % PORTNUM)
    server = SimpleWebSocketServer('', PORTNUM, Echo)
    signal.signal(signal.SIGINT, close_server)
    server.serveforever()
