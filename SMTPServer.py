import pickle
import socket
import threading

from pymongo.errors import ConnectionFailure

import globals_module
from CryptoService import CryptoService
from DataBaseServer import DataBaseService
from Email import Email
from File import File

SMTP_SERVER_IP = '192.168.0.181'
SMTP_SERVER_PORT = 1111


class SMTPServer:
    """
    Class representing a simple SMTP server.

    Attributes:
    - _port (int): The port on which the SMTP server is running.
    - _sock (socket.socket): The server socket.
    - _client_dict (dict): Dictionary to store client sockets.
    """

    def __init__(self, port):
        """
        Initialize the SMTP server.

        Parameters:
        - port (int): The port on which the SMTP server is running.
        """
        self._port = port
        self._sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client_dict: dict = {}
        self._is_client_available: dict = {}
        self._db = DataBaseService()
        self._running = True
        self._keys_dict = {}

    def __del__(self):
        """
        Destructor to clean up resources.
        """
        del self._db
        self._is_client_available.clear()
        self._client_dict.clear()
        self._keys_dict.clear()

    def _receive_email(self, client_sock: socket.socket):
        """
        Receive and process an email from a client.

        Parameters:
        - client_sock (socket.socket): The socket of the connected client.
        """
        email_addr = None
        try:
            key = CryptoService.generate_random_key()
            key_encrypted = key[::-1]
            client_sock.send(len(key_encrypted).to_bytes(4, byteorder="big"))
            client_sock.recv(3)
            client_sock.send(key_encrypted)

            enc_ack = CryptoService.encrypt_string("ACK", key)
            enc_len = len(enc_ack)  # This is the length of the received or sent ACK's, using the given key
            email_addr_len = int.from_bytes(client_sock.recv(4), byteorder='big')
            client_sock.send(enc_ack)
            email_addr = CryptoService.decrypt_string(client_sock.recv(email_addr_len).decode(), key)
            self._client_dict[email_addr] = client_sock
            self._is_client_available[email_addr] = True
            files = []
            client_sock.send(enc_ack)
            self._keys_dict[email_addr] = key
            while True:
                client_msg = CryptoService.decrypt_string(client_sock.recv(enc_len).decode(), key)
                print('client msg:',client_msg, email_addr)
                if not client_msg:
                    raise ConnectionRefusedError
                # Short messages like these will have length that is <= than 'ACK's
                if client_msg == 'CLSE':
                    enc_cmd = CryptoService.encrypt_string("-1", key)
                    client_sock.send(enc_cmd)
                    self._is_client_available[email_addr] = False
                    continue
                elif client_msg == 'OPEN':
                    self._is_client_available[email_addr] = True
                    continue
                # If client_msg is 'SEND'
                client_sock.send(enc_ack)
                files_list_length = int.from_bytes(client_sock.recv(4), byteorder='big')

                client_sock.send(enc_ack)

                files_list: [File] = pickle.loads(CryptoService.decrypt_obj(client_sock.recv(files_list_length), key))
                client_sock.send(enc_ack)

                pickle_mail_len = int.from_bytes(client_sock.recv(4), byteorder='big')

                client_sock.send(enc_ack)
                sent_email: Email = pickle.loads(CryptoService.decrypt_obj(client_sock.recv(pickle_mail_len), key))
                existing_emails = []
                for email in sent_email.recipients:
                    if self._db.email_to_mongo_obj(email) is not None:
                        existing_emails.append(email)
                shared_key = CryptoService.generate_files_key(existing_emails)
                print(existing_emails)
                print('shared key:', shared_key)
                for f in files_list:
                    files.append((f.name, f.extension, CryptoService.encrypt_obj(f.content, shared_key)))
                    print('content:', CryptoService.encrypt_obj(f.content, shared_key))
                files = self._save_files(files)
                new_id: str = self._send_email(sent_email, files)
                client_sock.send(enc_ack)
                for email in existing_emails:
                    try:
                        email = CryptoService.decrypt_b64(email[::-1])
                        if not (self._client_dict.get(email) is not None and self._is_client_available[email] is True):
                            continue
                        email_sock: socket.socket = self._client_dict[email]
                        enc_cmd = CryptoService.encrypt_string(new_id, self._keys_dict[email])
                        email_sock.send(enc_cmd)
                    except KeyError:
                        print(email, 'not found / connected at the moment')

                if files:
                    files.clear()

        except (socket.error, pickle.PickleError, EOFError) as e:
            print('----------------------SMTP error--------------------------', e, email_addr)
            if email_addr is not None:
                self._client_dict.pop(email_addr)
                self._is_client_available.pop(email_addr)
                self._keys_dict.pop(email_addr)
            client_sock.close()
            print("ERROR IN SERVER")

        except ConnectionFailure as e:
            print("-------------------------------------------Error in database server:-----------------------------",
                  e)
            self._running = False
            for email_final in self._client_dict.keys():
                self._client_dict[email_final].close()

    def start(self):
        """
        Start the SMTP server.
        """
        self._sock.bind((SMTP_SERVER_IP, self._port))
        self._sock.listen()
        print('server is up')
        try:
            while self._running:
                client_sock, client_address = self._sock.accept()
                client_thread = threading.Thread(target=self._receive_email, args=(client_sock,))
                client_thread.start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self._sock.close()

    def stop(self):
        """
        Stop the SMTP server.
        """
        self._sock.close()

    def _send_email(self, mailToSend: Email, files) -> str:
        """
        Sends an email to the database and return the ID.

        Parameters:
        - mailToSend (Email): The email to be sent.

        Returns:
        str: The ID of the stored email.
        """

        return self._db.store_email(CryptoService.encrypt_b64(mailToSend.sender)[::-1], mailToSend.recipients,
                                    CryptoService.encrypt_string(mailToSend.subject),
                                    CryptoService.encrypt_string(mailToSend.message),
                                    mailToSend.creation_date, files)

    def _save_files(self, files) -> list:
        return self._db.save_files(files)


if __name__ == "__main__":
    server = SMTPServer(SMTP_SERVER_PORT)
    server.start()
