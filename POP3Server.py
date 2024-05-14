import pickle
import socket
import threading

from pymongo.errors import ConnectionFailure

import globals_module
from CryptoService import CryptoService
from DataBaseServer import DataBaseService
from Email import Email

POP3_SERVER_IP = '192.168.0.181'
POP3_SERVER_PORT = 1112


class POP3Server:
    """
    Class representing a POP3 server.

    Attributes:
    - _socket: The socket for the server.
    - _dbService: An instance of the DataBaseService.
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

    def handle_client(self, client_sock):
        """
        Handle the client connection and commands.

        Parameters:
        - email (str): Client's email address.
        - client_sock (socket.socket): The socket for the client.
        """
        key = CryptoService.generate_random_key()
        key_encrypted = key[::-1]
        client_sock.send(len(key_encrypted).to_bytes(4, byteorder="big"))
        client_sock.recv(3)
        client_sock.send(key_encrypted)
        print('key:', key)
        enc_ack = CryptoService.encrypt_string("ACK", key)
        enc_len = len(enc_ack)  # This is the length of the received or sent ACK's, using the given key
        email_enc_len = int.from_bytes(client_sock.recv(4), byteorder='big')
        client_sock.send(enc_ack)
        email_addr = CryptoService.decrypt_string(client_sock.recv(email_enc_len).decode(), key)
        client_sock.send(enc_ack)
        try:
            while True:
                len_cmd = int.from_bytes(client_sock.recv(4), byteorder='big')
                client_sock.send(enc_ack)
                cmd = CryptoService.decrypt_string(client_sock.recv(len_cmd).decode(), key)
                client_sock.send(enc_ack)
                if not cmd:
                    raise ConnectionRefusedError

                elif cmd == 'RECV':
                    all_emails = self._dbService.get_all_received_emails(email_addr)

                    all_list_dict = [Email(m.get('sender').get('email'),
                                           [rec.get('email') for rec in m.get('recipients')],
                                           m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id')
                                           )
                                     for m in all_emails]

                    all_emails_dump = CryptoService.encrypt_obj(pickle.dumps(all_list_dict), key)
                    client_sock.send(len(all_emails_dump).to_bytes(4, byteorder="big"))
                    client_sock.recv(enc_len)
                    client_sock.send(all_emails_dump)
                elif cmd == 'SENT':
                    all_emails = self._dbService.get_all_sent_emails(email_addr)
                    all_list_dict = [Email(m.get('sender').get('email'),
                                           [rec.get('email') for rec in m.get('recipients')],
                                           m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id')
                                           )
                                     for m in all_emails]

                    all_emails_dump = CryptoService.encrypt_obj(pickle.dumps(all_list_dict), key)
                    client_sock.send(len(all_emails_dump).to_bytes(4, byteorder="big"))
                    client_sock.recv(enc_len)
                    client_sock.send(all_emails_dump)
                elif cmd == 'FILE_CON':
                    file_object_id_len = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(enc_ack)
                    file_object_id = CryptoService.decrypt_string(client_sock.recv(file_object_id_len), key)
                    file_content = CryptoService.decrypt_obj(self._dbService.get_file_content_by_id(file_object_id),
                                                             key)
                    client_sock.send(len(file_content).to_bytes(4, byteorder='big'))
                    client_sock.recv(enc_len)
                    client_sock.send(file_content)
                elif cmd == 'DELETE':
                    email_tup_length = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(enc_ack)
                    email_tup = pickle.loads(CryptoService.decrypt_obj(client_sock.recv(email_tup_length), key))
                    self._dbService.delete_email(email_tup)
                    client_sock.send(enc_ack)
                elif cmd == 'LOGIN':
                    client_tuple_length = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(enc_ack)
                    client_tuple = pickle.loads(CryptoService.decrypt_obj(client_sock.recv(client_tuple_length), key))
                    if email_addr in self._clients.keys():
                        client_dict_ans = {}
                    else:
                        client_dict_ans = self._dbService.authenticate_user(
                            CryptoService.encrypt_string_hash(client_tuple[0]),
                            CryptoService.encrypt_string_hash(client_tuple[1]))

                    client_dict_pickle = CryptoService.encrypt_obj(pickle.dumps(client_dict_ans), key)
                    client_sock.send(len(client_dict_pickle).to_bytes(4, byteorder='big'))
                    client_sock.recv(enc_len)
                    client_sock.send(client_dict_pickle)
                    if client_dict_ans == {}:
                        break
                    self._clients[email_addr] = client_sock
                elif cmd == 'REGISTER':
                    pickle_dumps_len = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(enc_ack)
                    pickle_dumps = pickle.loads(CryptoService.decrypt_obj(client_sock.recv(pickle_dumps_len), key))
                    if self._dbService.email_to_mongo_obj(pickle_dumps['email']) is not None:
                        client_sock.send(CryptoService.encrypt_string('F', key))
                        client_sock.close()
                        return
                    self._dbService.store_user(pickle_dumps['email'], pickle_dumps['password'],
                                               pickle_dumps['first_name'],
                                               pickle_dumps['last_name'], pickle_dumps['age'])
                    client_sock.send(CryptoService.encrypt_string('S', key))
                    self._clients[email_addr] = client_sock
                elif cmd[0:2] == "==":
                    mongo_email = self._dbService.find_email_by_id(CryptoService.decrypt_string(cmd[2:], key))
                    email_obj = Email(mongo_email.get('sender').get('email'),
                                      [rec.get('email') for rec in mongo_email.get('recipients')],
                                      mongo_email.get('subject'), mongo_email.get('message')
                                      , mongo_email.get('creation_date'), mongo_email.get('_id'))

                    mongo_email_dump = CryptoService.encrypt_obj(pickle.dumps(email_obj), key)
                    client_sock.send(len(mongo_email_dump).to_bytes(4, byteorder='big'))
                    client_sock.recv(enc_len)
                    client_sock.send(mongo_email_dump)
                else:
                    mongo_email = self._dbService.find_email_by_id(CryptoService.decrypt_string(cmd, key))
                    files_info = [(f_id,) + self._dbService.get_file_name_ex_key_by_id(f_id) for f_id in
                                  mongo_email.get('files')]

                    mongo_email_dump = CryptoService.encrypt_obj(pickle.dumps(files_info), key)
                    client_sock.send(len(mongo_email_dump).to_bytes(4, byteorder='big'))
                    client_sock.recv(enc_len)
                    client_sock.send(mongo_email_dump)
                client_sock.recv(enc_len)  # Final ACK after all operations
        except (socket.error, pickle.PickleError, EOFError, ConnectionAbortedError, ConnectionRefusedError) as e:
            print("-------------------------------------------Error in pop3 server:-----------------------------", e)
            client_sock.close()
            self._clients.pop(email_addr)
        except ConnectionFailure as e:
            print("-------------------------------------------Error in database server:-----------------------------",
                  e)
            self._running = False
            for con in self._clients:
                self._clients[con].close()

    def run(self):
        """
        Runs the POP3 server.
        """
        self._socket.bind((POP3_SERVER_IP, POP3_SERVER_PORT))
        self._socket.listen()
        print('POP3 is up')
        try:
            while self._running:
                client_sock, addr = self._socket.accept()
                threading.Thread(target=self.handle_client, args=(client_sock,)).start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self._socket.close()


if __name__ == "__main__":
    server = POP3Server()
    server.run()
