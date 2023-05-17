import threading
import socket
from passwordStrengthMeter_main import *
from maliciousURL_detector import *
from AES_functions import *
from malicious_file_detector import *
from sql_database import *


class Server:
    def __init__(self, ip, port):
        """The function receives the server's IP address and port number as parameters.
        This function builds a server object accordingly."""
        self.IP = ip
        self.PORT = port
        self.list_of_obj_clients = []  # List of all the objects which represent each connected client
        self.list_of_ip_clients = []  # List of IP address of each connected client

    def open_socket(self):
        """The function doesn't receive any parameters.
        This function opens the server's socket."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def open_server(self):
        """The function doesn't receive any parameters.
        This function opens the server and makes it wait for incoming clients."""
        self.server.bind((self.IP, self.PORT))
        self.server.listen()
        print("SERVER is waiting for clients")

    def end_specific_connection(self, conn_obj):
        """The function receives a client socket object as a parameter.
        This function is activated by entering receiving the string 'end'.
        This function disconnects the client and removes his kept data."""
        client_index = self.list_of_obj_clients.index(conn_obj)
        self.list_of_obj_clients.remove(self.list_of_obj_clients[client_index])
        self.list_of_ip_clients.remove(self.list_of_ip_clients[client_index])
        conn_obj.close()  # Close this specific connection due to client's preference

    def choice2(self, conn_obj, URL):
        """The function receives a client socket object and a URL as parameters.
        This function is activated by having the client use the malicious URL detector service.
        This function checks its legitimacy of the supplied URL address (using a
        different function), and sends the final answer to the client."""
        engine_result = MurlD_main(URL)  # Check if URL is malicious
        conn_obj.send(engine_result.encode())

    def choice3(self, conn_obj, client_port, encrypted_pass):
        """The function receives a client socket object, port number, and an encrypted password
        in the AES algorithm as parameters.
        This function is activated by having the client use the password strength meter service.
        This function decrypts the supplied password, checks its strength, and then sends
        the final answer to the client."""
        fernet_obj = fernet_obj_generator(client_port)  # Generates a Fernet object
        decrypted_pass = AES_decrypt(encrypted_pass, fernet_obj)  # Decode the password using the Fernet object
        engine_result = PSM_main(decrypted_pass)  # Check password strength
        conn_obj.send(engine_result.encode())

    def choice4(self, conn_obj, file_path):
        """The function receives a client socket object as parameter.
        This function is activated by having the client uploading a non-empty executable
        (exe) file in the malicious file detector page.
        This function checks the legitimacy of the file, which is received by the client when
        calling the function 'receive_file', and then sends the final answer to the client."""
        with open(f"{file_path}", "wb") as f:
            while True:
                data = conn_obj.recv(1024)
                if not data:
                    break
                if data == b"end":
                    return "end"
                if b"done" in data:
                    break
                else:
                    try:
                        if data == b"done":
                            break
                    except:
                        pass
                f.write(data)
        engine_result = DMF_main(file_path)  # Checks if file is malicious
        conn_obj.send(engine_result.encode())
        return "continue"  # Means client is still connected

    def client_login(self, conn_obj, username, password):
        """The function receives a client socket object, a username, and the username's
        password as parameters.
        This function is activated by having the client enter a non-empty password and
        a non-empty username in the login page.
        This function checks if the user exists in the SQLite database, using a different
        function, and sends the result to the client."""
        sql_checkUser = f"""SELECT ID FROM 'UsersInfo' where username='{username}' AND
                        password='{password}';"""
        if check_user(sql_checkUser):
            conn_obj.send("true".encode())   # user exists in the database
        else:
            conn_obj.send("false".encode())  # user doesn't exist in the database

    def is_username_exist(self, conn_obj, username):
        """The function receives a client socket object and a username as parameters.
        This function is activated by having the client enter the same password in both
        entry boxes and a non-empty: password, confirmation password, and username, on the
        signup page.
        This function checks if the username already exists in the SQLite database, using a
        different function, and sends the result to the client."""
        if not check_user(f"SELECT ID FROM 'UsersInfo' where username='{username}';"):
            conn_obj.send("false".encode())
        else:
            conn_obj.send("true".encode())

    def new_user(self, username, password):
        """The function receives a client socket object, a username, and the username's
        password as parameters.
        This function is activated by having the client enter proper data on the signup page.
        This function adds the user's data to the SQLite database, making him a new signed user."""
        sql_addUser = f"""INSERT INTO UsersInfo (username,password) VALUES('{username}',
                      '{password}');"""
        db_adduser(sql_addUser)  # Add user to the database

    def is_password_strong(self, client_port, conn_obj, encrypted_password):
        """The function receives the client's port number, a client socket object, and an encrypted password
        in the AES algorithm as parameters.
        This function is activated by having the client pass the rest of the checks when
        signing up.
        This function decrypts the supplied password, checks if it is strong enough, and then
        sends the final answer to the client."""
        fernet_obj = fernet_obj_generator(client_port)  # Generates a Fernet object
        decoded_password = AES_decrypt(encrypted_password,fernet_obj)  # Decode the password using the Fernet object
        pass_strength = PSM_main(decoded_password)  # Check password strength
        if "weak" in pass_strength:
            conn_obj.send("false".encode())  # Password isn't strong enough
        else:
            conn_obj.send("true".encode())  # Password is strong enough

    def connect_client(self, conn_obj, client_port):
        """The function receives a client socket object and its port number as parameters.
        This function is first activated by having the client connect to the server.
        This function sends the client his port, afterwards it receives the client choice
        of service and activates a different function according to the choice."""
        conn_obj.send(str(client_port).encode())
        count = 0
        while True:
            clients_choice = conn_obj.recv(1024).decode()
            if clients_choice.lower() == "end":  # Client wishes to disconnects from the service
                self.end_specific_connection(conn_obj)
                break
            elif clients_choice == "login":
                login_data = conn_obj.recv(1024).decode().split(',')
                self.client_login(conn_obj, login_data[0], login_data[1])  # Check if client exists
            elif clients_choice == "name exists?":
                checkUser_data = conn_obj.recv(1024).decode()
                self.is_username_exist(conn_obj, checkUser_data)
            elif clients_choice == "add user":
                newUser_data = conn_obj.recv(1024).decode().split(',')
                self.new_user(newUser_data[0], newUser_data[1])
            elif clients_choice == "test password strength":
                encrypted_password = conn_obj.recv(1024).decode()
                self.is_password_strong(client_port, conn_obj, encrypted_password)
            elif clients_choice == "choice2":  # Checks if URL is malicious
                suspicious_url = conn_obj.recv(1024).decode()
                self.choice2(conn_obj, suspicious_url)
            elif clients_choice == "choice3":  # Check password strength
                encrypted_engine3_password = conn_obj.recv(1024).decode()
                self.choice3(conn_obj, client_port, encrypted_engine3_password)
            elif clients_choice == "choice4":  # Checks if file is malicious
                file_path = os.getcwd() + f"\\{self.conn_address[0]}{client_port}{count}.exe"
                count += 1
                is_end = self.choice4(conn_obj, file_path)
                if is_end == "end":
                    self.end_specific_connection(conn_obj)
                    break


    def get_clients(self):
        """The function doesn't receive any parameters.
        This function accepts each of the incoming clients and saves their IP address and obj,
        afterwards each client is sent to the 'connect_client' function on its own thread. If
        something goes wrong a message indicates an error will be printed."""
        while True:
            try:
                self.conn_obj, self.conn_address = self.server.accept()
                self.list_of_ip_clients.append(self.conn_address)
                self.list_of_obj_clients.append(self.conn_obj)
                print(self.list_of_ip_clients)
                conn_thread = threading.Thread(target=Server.connect_client, args=(self, self.conn_obj, self.conn_address[1]))
                conn_thread.start()  # Start new thread for each client
            except:
                pass


sPort = 4444
server1 = Server("192.168.1.51", sPort)
server1.open_socket()
server1.open_server()
server1.get_clients()
