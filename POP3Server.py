import pickle
import socket
import threading

import globals_module
from Base64 import Base64
from DataBaseServer import DataBaseService
from Mail import Mail

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

    def __del__(self):
        """
        Destructor to clean up resources.
        """
        if hasattr(self, '_dbService'):
            del self._dbService

    def handle_client(self, email, client_sock):
        """
        Handle the client connection and commands.

        Parameters:
        - email (str): Client's email address.
        - client_sock: The socket for the client.
        """
        try:
            while True:
                # Receive command from the client
                cmd = client_sock.recv(1024).decode()
                print('cmd is:', cmd)
                if not cmd:
                    break

                # Handle different commands received from the client
                if cmd == 'exit':
                    client_sock.close()
                    break
                elif cmd == 'recv':
                    # Retrieve all received mails for the client's email
                    all_mails = self._dbService.get_all_received_mails(email)

                    # Convert MongoDB documents to Mail objects
                    all_list_dict = [Mail(m.get('sender').get('email'),
                                          [rec.get('email') for rec in m.get('recipients')],
                                          m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id')
                                          )
                                     for m in all_mails]
                    # Serialize and send the list of mails to the client
                    all_mails_dump = pickle.dumps(all_list_dict)
                    print('sent int:::', client_sock.send(str(len(all_mails_dump)).encode()))
                    client_sock.recv(3)
                    client_sock.send(all_mails_dump)
                elif cmd == 'sent':
                    # Retrieve all sent mails for the client's email
                    all_mails = self._dbService.get_all_sent_mails(email)

                    # Convert MongoDB documents to Mail objects
                    all_list_dict = [Mail(m.get('sender').get('email'),
                                          [rec.get('email') for rec in m.get('recipients')],
                                          m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id')
                                          )
                                     for m in all_mails]
                    # Serialize and send the list of mails to the client
                    all_mails_dump = pickle.dumps(all_list_dict)
                    print('sent int:::', client_sock.send(str(len(all_mails_dump)).encode()))
                    client_sock.recv(3)
                    client_sock.send(all_mails_dump)
                elif cmd == 'file_con':
                    client_sock.send(b'ACK')
                    file_object_id = client_sock.recv(globals_module.OBJECT_ID_LENGTH).decode()
                    file_content = self._dbService.get_file_content_by_id(file_object_id)
                    client_sock.send(len(file_content).to_bytes(4, byteorder='big'))
                    client_sock.recv(3)
                    client_sock.send(file_content)
                elif cmd == 'delete':
                    client_sock.send(b'ACK')
                    mail_tup_length = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(b'ACK')
                    mail_tup = pickle.loads(client_sock.recv(mail_tup_length))
                    self._dbService.delete_mail(mail_tup)
                    print("DELETE TUP:", mail_tup)
                    client_sock.send(b'ACK')
                elif cmd == 'login':
                    client_sock.send(b'ACK')
                    len_tuple = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(b'ACK')
                    client_tuple = pickle.loads(client_sock.recv(len_tuple)[4:])
                    client_dict_ans = self._dbService.authenticate_user(Base64.Decrypt(client_tuple[0]),
                                                                        Base64.Decrypt(client_tuple[1]))
                    client_dict_pickle = b'abcd' + pickle.dumps(client_dict_ans)
                    client_sock.send(len(client_dict_pickle).to_bytes(4, byteorder='big'))
                    client_sock.recv(3)
                    client_sock.send(client_dict_pickle)
                    if client_dict_ans == {}:
                        break
                else:
                    # Retrieve a single mail by its ID and send it to the client
                    # TODO -> send only the file names, no need for sending the whole Mail again
                    mongo_mail = self._dbService.find_email_by_id(cmd)
                    files_info = [(f_id,) + self._dbService.get_file_name_ex_by_id(f_id) for f_id in
                                  mongo_mail.get('files')]
                    single_mail_obj = Mail(mongo_mail.get('sender').get('email'),
                                           [mail.get('email') for mail in mongo_mail.get('recipients')],
                                           mongo_mail.get('subject'), mongo_mail.get('message'),
                                           mongo_mail.get('creation_date'), mongo_mail.get('_id'),
                                           files_info)

                    mongo_mail_dump = pickle.dumps(single_mail_obj)
                    client_sock.send(len(mongo_mail_dump).to_bytes(4, byteorder='big'))
                    client_sock.recv(3)
                    client_sock.send(mongo_mail_dump)
        except socket.error as e:
            print("Socket Error:", e)
        finally:
            client_sock.close()

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
            while True:
                # Accept incoming client connection
                client_sock, addr = self._socket.accept()
                # Receive client's email
                client_email = client_sock.recv(1024).decode()
                # Check if client_email is a valid email address
                if len(client_email) > 0 and '@' in client_email:
                    # Send acknowledgment to the client
                    client_sock.send(b'ack')
                    # Create a new thread to handle the client
                    threading.Thread(target=self.handle_client, args=(client_email, client_sock,)).start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            # Close the server socket
            self._socket.close()


# Entry point of the script
if __name__ == "__main__":
    # Create and run the POP3 server
    server = POP3Server()
    server.run()
