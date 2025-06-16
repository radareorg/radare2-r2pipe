#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mock R2 Server for Testing

This module provides HTTP and TCP servers that mimic basic radare2 server
functionality for testing r2pipe network capabilities.
"""

import json
import socket
import threading
import http.server
import socketserver
import argparse
import time
import sys
import os
import re
import signal

# Default ports
DEFAULT_HTTP_PORT = 9090
DEFAULT_TCP_PORT = 9080

# Store active servers for clean shutdown
SERVERS = []

class MockR2Handler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for mock r2 server"""
    
    # Basic r2 commands and their responses
    COMMANDS = {
        # Version info
        "v": "radare2 mock server\n",
        "?V": "radare2 mock server\n",
        
        # Basic info
        "i": """arch     x86
        bits     64
        os       linux
        minopsz  1
        maxopsz  16
        endian   little
        """,
        
        # JSON info
        "ij": {"core":{"type":"mock","file":"mock","fd":42,"size":1024,"humansz":"1K","iorw":true,"mode":"r-x","obsz":0,"block":256,"format":"elf64"},"bin":{"arch":"x86","bits":64,"os":"linux"}},
        
        # Disassembly
        "pd 1": "            0x00400000      55             push rbp\n",
        "pd 2": "            0x00400000      55             push rbp\n            0x00400001      4889e5         mov rbp, rsp\n",
        "pd 5": "            0x00400000      55             push rbp\n            0x00400001      4889e5         mov rbp, rsp\n            0x00400004      4883ec10       sub rsp, 0x10\n            0x00400008      897dfc         mov dword [rbp - 4], edi\n            0x0040000b      488975f0       mov qword [rbp - 0x10], rsi\n",
        
        # JSON disassembly
        "pdj 1": [{"offset":4194304,"size":1,"opcode":"push rbp","bytes":"55","type":"rpush","stack":"sym.main"}],
        "pdj 2": [{"offset":4194304,"size":1,"opcode":"push rbp","bytes":"55","type":"rpush","stack":"sym.main"},{"offset":4194305,"size":3,"opcode":"mov rbp, rsp","bytes":"4889e5","type":"mov","stack":"sym.main"}],
        
        # Hexdump
        "px 10": "0x00400000  5548 89e5 4883 ec10 897d fc48  UH..H....}.H\n",
        
        # Raw bytes
        "p8 10": "554889e548",
        
        # Echo command
        "?e hello": "hello\n",
        "?e world": "world\n",
        "?e hello\n?e world": "hello\nworld\n",
        
        # Default response for unknown commands
        "default": "",
    }
    
    def do_GET(self):
        """Handle GET requests"""
        # Parse URL path which contains the command
        if self.path.startswith("/cmd/"):
            # Extract command from URL
            cmd = self.path[5:]
            
            # URL decode
            import urllib.parse
            cmd = urllib.parse.unquote(cmd)
            
            # Log the command
            print(f"[HTTP] Received command: {cmd}")
            
            # Process the command
            response = self.process_command(cmd)
            
            # Send response
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.send_header("Content-Length", len(response))
            self.end_headers()
            
            # Write response
            self.wfile.write(response.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
    
    def process_command(self, cmd):
        """Process an r2 command and return the response"""
        # Check for exact match
        if cmd in self.COMMANDS:
            result = self.COMMANDS[cmd]
            # If result is a dict or list, convert to JSON
            if isinstance(result, (dict, list)):
                return json.dumps(result)
            return result
        
        # Check for commands with parameters
        for pattern, response in self.COMMANDS.items():
            # Convert r2 command pattern to regex pattern
            if " " in pattern:
                cmd_base = pattern.split(" ")[0]
                if cmd.startswith(cmd_base):
                    # Extract parameters
                    params = cmd[len(cmd_base):].strip()
                    if params.isdigit():
                        # Numeric parameter, like pd 10 or px 20
                        return self.handle_parameterized_command(cmd_base, int(params), response)
            
            # Handle combined commands with semicolons or newlines
            if ";" in cmd or "\n" in cmd:
                return self.handle_combined_command(cmd)
        
        # Default response
        return self.COMMANDS.get("default", "")
    
    def handle_parameterized_command(self, cmd_base, param, template_response):
        """Handle commands with numeric parameters like pd 10 or px 20"""
        if cmd_base == "pd":
            # Scale disassembly based on parameter
            if isinstance(template_response, list):
                # pdj command
                return json.dumps(template_response * min(param, 10))
            else:
                # pd command
                lines = template_response.splitlines()
                # Limit to prevent huge responses
                param = min(param, 100)
                result = []
                for i in range(param):
                    offset = 0x400000 + i * 3  # Simple address increment
                    instr = f"            0x{offset:08x}      {55+i:02x}             push r{9+i}\n"
                    result.append(instr)
                return "".join(result)
        
        elif cmd_base == "px":
            # Scale hexdump based on parameter
            lines_needed = (param + 15) // 16  # 16 bytes per line
            # Limit to prevent huge responses
            lines_needed = min(lines_needed, 1000)
            result = []
            for i in range(lines_needed):
                offset = 0x400000 + i * 16
                bytes_data = " ".join([f"{(55+j):02x}{(66+j):02x}" for j in range(8)])
                ascii_data = "".join([chr((55+j) % 26 + 65) for j in range(16)])
                result.append(f"0x{offset:08x}  {bytes_data}  {ascii_data}")
            return "\n".join(result) + "\n"
        
        elif cmd_base == "p8":
            # Raw bytes output
            # Limit to prevent huge responses
            param = min(param, 1000)
            return "".join([f"{(55+i)%256:02x}" for i in range(param)])
        
        # Default: return the template response
        return template_response
    
    def handle_combined_command(self, cmd):
        """Handle commands combined with ; or newline"""
        # Split by both ; and newline
        parts = re.split(r';|\n', cmd)
        result = []
        
        for part in parts:
            part = part.strip()
            if part:
                response = self.process_command(part)
                result.append(response)
        
        return "".join(result)
    
    def log_message(self, format, *args):
        """Override to reduce log noise"""
        return


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server to handle concurrent connections"""
    pass


class MockR2TCPHandler(socketserver.BaseRequestHandler):
    """TCP handler for mock r2 server"""
    
    def handle(self):
        """Handle TCP connection"""
        # Reuse the command processor from HTTP handler
        processor = MockR2Handler
        
        try:
            while True:
                # Receive command
                data = self.request.recv(1024)
                if not data:
                    break
                
                # Decode command
                cmd = data.decode("utf-8").strip()
                print(f"[TCP] Received command: {cmd}")
                
                # Process command
                response = processor.process_command(None, cmd)
                
                # Send response
                self.request.sendall(response.encode("utf-8"))
                
                # TCP in r2pipe often expects connection to close after command
                break
        
        except Exception as e:
            print(f"Error handling TCP connection: {e}")
        finally:
            self.request.close()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server to handle concurrent connections"""
    allow_reuse_address = True


def start_http_server(port=DEFAULT_HTTP_PORT):
    """Start the HTTP mock server"""
    try:
        server = ThreadedHTTPServer(("127.0.0.1", port), MockR2Handler)
        print(f"Starting HTTP mock r2 server on port {port}")
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        SERVERS.append(server)
        return server
    except Exception as e:
        print(f"Failed to start HTTP server: {e}")
        return None


def start_tcp_server(port=DEFAULT_TCP_PORT):
    """Start the TCP mock server"""
    try:
        server = ThreadedTCPServer(("127.0.0.1", port), MockR2TCPHandler)
        print(f"Starting TCP mock r2 server on port {port}")
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        SERVERS.append(server)
        return server
    except Exception as e:
        print(f"Failed to start TCP server: {e}")
        return None


def shutdown_servers():
    """Shutdown all servers"""
    for server in SERVERS:
        server.shutdown()
        server.server_close()
    print("All servers shut down")


def signal_handler(sig, frame):
    """Handle Ctrl+C and other signals"""
    print("Shutting down mock servers...")
    shutdown_servers()
    sys.exit(0)


def main():
    """Run the mock server"""
    parser = argparse.ArgumentParser(description='Mock R2 Server for testing')
    parser.add_argument('--http', type=int, default=DEFAULT_HTTP_PORT, 
                        help=f'HTTP port (default: {DEFAULT_HTTP_PORT})')
    parser.add_argument('--tcp', type=int, default=DEFAULT_TCP_PORT, 
                        help=f'TCP port (default: {DEFAULT_TCP_PORT})')
    parser.add_argument('--http-only', action='store_true', 
                        help='Start HTTP server only')
    parser.add_argument('--tcp-only', action='store_true', 
                        help='Start TCP server only')
    
    args = parser.parse_args()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if not args.tcp_only:
            http_server = start_http_server(args.http)
        
        if not args.http_only:
            tcp_server = start_tcp_server(args.tcp)
        
        print("Servers started. Press Ctrl+C to exit.")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("Interrupted by user")
    
    finally:
        shutdown_servers()


if __name__ == "__main__":
    main()