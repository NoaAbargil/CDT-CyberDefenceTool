import socket
from block_vulnerable_ports import *
from update_patches import *


class Client:
    def __init__(self, destination_ip, destination_port):
        """Function receives the destination server's IP address and port number as parameters.
        This function builds a client object accordingly."""
        self.dst_ip = destination_ip  # server's IP address
        self.dst_port = destination_port  # server's port number

    def open_socket(self):
        """Function doesn't receive any parameters.
        This function opens the client's socket."""
        self.client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_client_to_server(self):
        """Function doesn't receive any parameters.
        This function connects the client's socket to the server's socket"""
        self.client_conn.connect((self.dst_ip, self.dst_port))

    def close_socket(self):
        """Function doesn't receive any parameters.
        This function closes the client's socket."""
        self.client_conn.close()

    def send_message(self, msg, encode=True):
        """Function receive a message and an encoding flag as parameters.
        This function encodes the supplied message if the given flag is True, otherwise, it
        does not encode the supplied message. Finally, the message is sent to the server."""
        if encode:
            self.client_conn.send(msg.encode())
        else:
            self.client_conn.send(msg)

    def receive_message(self):
        """Function doesn't receive any parameters.
        This function receives a message from the server, decodes and then returns it."""
        return self.client_conn.recv(1024).decode()

    def send_file(self, file_path):
        """Function receives a file path as parameter.
        This function is activated by uploading a non-empty exe file in the
        malicious file detector page.
        This function sends the file to the server and closes the file in the end."""
        with open(file_path, "rb") as f:  # Send the executable file to the server
            data = f.read(1024)
            while data:
                self.client_conn.send(data)
                data = f.read(1024)
        self.client_conn.send(b"done")  # Sign for server to stop the file transfer

    def choice1(self, level, my_port):
        """Function receives level of protection and client's port as parameters.
        This function is activated by picking any protection level in the combobox which is
        in the block vulnerabilities page.
        This function activates the protection programs according to the given protection
        level, and returns a tuple which represent a short summery of the programs actions."""
        updated_patches = 0
        if level in ["Expert", "Advanced"]:
            updated_patches = UP_main()  # For both expert and advanced protection request
            if level == "Expert":  # Highest protection level
                blocked_ports = BVP_main("high", my_port, self.dst_port)  # For expert protection request
            else:  # For advanced protection request
                blocked_ports = BVP_main("low", my_port, self.dst_port)
        else:  # For basic protection request
            blocked_ports = BVP_main("low", my_port, self.dst_port)  # Lowest protection level
        return (blocked_ports, updated_patches)
