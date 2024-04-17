import pickle
import socket
import threading

import globals_module
from Base64 import Base64
from DataBaseServer import DataBaseService
from Email import Email
from pymongo.errors import ConnectionFailure
from random import choice

# Constants for POP3 server configuration
POP3_SERVER_IP = '192.168.0.181'
POP3_SERVER_PORT = 1112


class POP3Server:
    """
    Class representing a POP3 server.

    Attributes:
    - _socket: The socket for the server.
    - _dbService: An instance of the DataBaseService.

    Methods:
    - __init__: Initialize the POP3 server.
    - __del__: Destructor to clean up resources.
    - handle_client: Handle the client connection and commands.
    - run: Run the POP3 server.
    """

    def __init__(self):
        """
        Initialize the POP3 server.
        """
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._dbService = DataBaseService()
        self._clients = {}
        self._running = True

    def __del__(self):
        """
        Destructor to clean up resources.
        """
        del self._dbService
        self._clients.clear()

    def handle_client(self, email, client_sock):
        """
        Handle the client connection and commands.

        Parameters:
        - email (str): Client's email address.
        - client_sock: The socket for the client.
        """
        try:
            while True:
                print('talking to:', email)

                # Receive command from the client
                cmd = client_sock.recv(1024).decode()
                print('cmd is:', cmd)
                if not cmd:
                    raise ConnectionRefusedError

                elif cmd == 'RECV':

                    print('mail here is:', email)
                    # Retrieve all received emails for the client's email
                    all_emails = self._dbService.get_all_received_emails(email)

                    # Convert MongoDB documents to Email objects
                    all_list_dict = [Email(m.get('sender').get('email'),
                                           [rec.get('email') for rec in m.get('recipients')],
                                           m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id')
                                           )
                                     for m in all_emails]
                    # Serialize and send the list of emails to the client
                    random_prefix = ''.join(choice(globals_module.ASCII_LETTERS) for _ in range(4))
                    all_emails_dump = random_prefix.encode() + pickle.dumps(all_list_dict)
                    client_sock.send(len(all_emails_dump).to_bytes(4, byteorder="big"))
                    client_sock.recv(3)
                    client_sock.send(all_emails_dump)
                elif cmd == 'SENT':
                    # Retrieve all sent emails for the client's email
                    all_emails = self._dbService.get_all_sent_emails(email)

                    # Convert MongoDB documents to Eemail objects
                    all_list_dict = [Email(m.get('sender').get('email'),
                                           [rec.get('email') for rec in m.get('recipients')],
                                           m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id')
                                           )
                                     for m in all_emails]
                    # Serialize and send the list of emails to the client
                    random_prefix = ''.join(choice(globals_module.ASCII_LETTERS) for _ in range(4))
                    all_emails_dump = random_prefix.encode() + pickle.dumps(all_list_dict)
                    client_sock.send(len(all_emails_dump).to_bytes(4, byteorder="big"))
                    client_sock.recv(3)
                    client_sock.send(all_emails_dump)
                elif cmd == 'FILE_CON':
                    client_sock.send(b'ACK')
                    file_object_id = client_sock.recv(globals_module.OBJECT_ID_LENGTH).decode()
                    file_content = self._dbService.get_file_content_by_id(file_object_id)[::-1]
                    client_sock.send(len(file_content).to_bytes(4, byteorder='big'))
                    client_sock.recv(3)
                    client_sock.send(file_content)
                elif cmd == 'DELETE':
                    client_sock.send(b'ACK')
                    email_tup_length = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(b'ACK')
                    email_tup = pickle.loads(client_sock.recv(email_tup_length)[::-1])
                    self._dbService.delete_email(email_tup)
                    print("DELETE TUP:", email_tup)
                    client_sock.send(b'ACK')
                elif cmd == 'LOGIN':
                    client_sock.send(b'ACK')
                    len_tuple = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(b'ACK')
                    client_tuple = pickle.loads(client_sock.recv(len_tuple)[4:])
                    if email in self._clients.keys():
                        client_dict_ans = {}
                    else:
                        client_dict_ans = self._dbService.authenticate_user(client_tuple[0],
                                                                            client_tuple[1])
                    random_prefix = ''.join(choice(globals_module.ASCII_LETTERS) for _ in range(4))
                    client_dict_pickle = random_prefix.encode() + pickle.dumps(client_dict_ans)
                    client_sock.send(len(client_dict_pickle).to_bytes(4, byteorder='big'))
                    client_sock.recv(3)
                    client_sock.send(client_dict_pickle)
                    if client_dict_ans == {}:
                        break
                    self._clients[email] = client_sock
                elif cmd == 'REGISTER':
                    client_sock.send(b'ACK')
                    pickle_dumps_len = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(b'ACK')
                    pickle_dumps = pickle.loads(client_sock.recv(pickle_dumps_len)[4:][::-1])
                    if self._dbService.email_to_mongo_obj(pickle_dumps['email']) is not None:
                        client_sock.send(b'F')
                        client_sock.close()
                        return
                    self._dbService.store_user(pickle_dumps['email'], pickle_dumps['password'],
                                               pickle_dumps['first_name'],
                                               pickle_dumps['last_name'], pickle_dumps['age'])
                    client_sock.send(b'S')
                    self._clients[email] = client_sock
                elif cmd[0:2] == "==":
                    mongo_email = self._dbService.find_email_by_id(Base64.Decrypt(cmd[2:]))
                    email_obj = Email(mongo_email.get('sender').get('email'),
                                      [rec.get('email') for rec in mongo_email.get('recipients')],
                                      mongo_email.get('subject'), mongo_email.get('message')
                                      , mongo_email.get('creation_date'), mongo_email.get('_id'))
                    random_prefix = ''.join(choice(globals_module.ASCII_LETTERS) for _ in range(4))
                    mongo_email_dump = random_prefix.encode() + pickle.dumps(email_obj)
                    client_sock.send(len(mongo_email_dump).to_bytes(4, byteorder='big'))
                    client_sock.recv(3)
                    client_sock.send(mongo_email_dump)
                else:
                    # Retrieve a single email by its ID and send it to the client
                    mongo_email = self._dbService.find_email_by_id(Base64.Decrypt(cmd))
                    files_info = [(f_id,) + self._dbService.get_file_name_ex_by_id(f_id) for f_id in
                                  mongo_email.get('files')]

                    random_prefix = ''.join(choice(globals_module.ASCII_LETTERS) for _ in range(4))
                    mongo_email_dump = random_prefix.encode() + pickle.dumps(files_info)
                    client_sock.send(len(mongo_email_dump).to_bytes(4, byteorder='big'))
                    client_sock.recv(3)
                    client_sock.send(mongo_email_dump)
        except (socket.error, pickle.PickleError) as e:
            print("-------------------------------------------Error in pop3 server:-----------------------------", e)
            client_sock.close()
            self._clients.pop(email)
        except ConnectionFailure as e:
            print("-------------------------------------------Error in database server:-----------------------------",
                  e)
            self._running = False
            for con in self._clients:
                self._clients[con].close()

    def run(self):
        """
        Run the POP3 server.
        """
        # Bind socket to IP and port
        self._socket.bind((POP3_SERVER_IP, POP3_SERVER_PORT))
        # Start listening for incoming connections
        self._socket.listen()
        print('POP3 is up')
        try:
            while self._running:
                # Accept incoming client connection
                client_sock, addr = self._socket.accept()
                # Receive client's email
                client_email = client_sock.recv(1024).decode()
                print('new connection from:', client_email)
                # Check if client_email is a valid email address
                client_sock.send(b'ACK')
                # Create a new thread to handle the client
                threading.Thread(target=self.handle_client, args=(client_email, client_sock,)).start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            # Close the server socket
            self._socket.close()


# Entry point of the script
if __name__ == "__main__":
    server = POP3Server()
    server.run()
