import pickle
import socket
import threading

from Base64 import Base64
from DataBaseServer import DataBaseService
from File import File
from Email import Email

SMTP_SERVER_IP = '192.168.0.181'
SMTP_SERVER_PORT = 1111


class SMTPServer:
    """
    Class representing a simple SMTP server.

    Attributes:
    - _port (int): The port on which the SMTP server is running.
    - _sock (socket.socket): The server socket.
    - _client_dict (dict): Dictionary to store client sockets.

    Methods:
    - __init__: Initialize the SMTP server.
    - _receive_email: Receive and process an email from a client.
    - start: Start the SMTP server.
    - stop: Stop the SMTP server.
    - _send_email: Send an email to the database and return the ID.
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

    def _receive_email(self, client_sock: socket.socket):
        """
        Receive and process an email from a client.

        Parameters:
        - client_sock (socket.socket): The socket of the connected client.
        """
        email_addr = None
        try:
            email_addr = client_sock.recv(1024).decode()
            self._client_dict[email_addr] = client_sock
            self._is_client_available[email_addr] = True
            files = []
            client_sock.send(b'ACK')
            while True:
                print("HELLO ITS ME, talking to:", email_addr)
                files.clear()
                client_msg = client_sock.recv(4)
                print('client_msg:', client_msg)
                if client_msg == b'CLSE':
                    client_sock.send(b'-1')
                    print('sent -1')
                    self._is_client_available[email_addr] = False
                    continue
                elif client_msg == b'OPEN':
                    self._is_client_available[email_addr] = True
                    continue

                files_list_length = int.from_bytes(client_msg, byteorder='big')
                print("GPT SOME", files_list_length)
                client_sock.send(b'ACK')
                m = client_sock.recv(files_list_length)
                print(len(m))

                files_list: [File] = pickle.loads(m[4:])
                client_sock.send(b'ACK')
                for f in files_list:
                    files.append((Base64.Decrypt(f.name), Base64.Decrypt(f.extension), f.content[::-1]))

                pickle_mail_len = int.from_bytes(client_sock.recv(4), byteorder='big')
                client_sock.send(b'ACK')
                print('sent an ack for this shit')
                sentMail: Email = pickle.loads(client_sock.recv(pickle_mail_len))
                #TODO - maybe dont create from constructor
                print('id of sent email:', id(sentMail))
                sentMail = Email(sentMail.sender, [i for i in sentMail.recipients],
                                 sentMail.subject, sentMail.message,
                                 sentMail.creation_date)

                print('RECEIVED', sentMail.recipients, sentMail.message, sentMail.subject, sentMail.creation_date,
                      sentMail.sender)
                if files:
                    files = SMTPServer._save_files(files)

                new_id: str = SMTPServer._send_email(sentMail, files)
                print(self._client_dict)
                print(self._is_client_available)
                for email in sentMail.recipients:
                    try:

                        if not (self._client_dict.get(email) is not None and self._is_client_available[email] is True):
                            print('):')
                            continue
                        print("SENT:", files)
                        email_sock: socket.socket = self._client_dict[email]
                        email_sock.send(Base64.Encrypt(new_id).encode())
                        print('sent', new_id.encode(), 'to', email, type(new_id), new_id)
                        print("SENT BY SOCKET TO", email)
                    except KeyError:
                        print(email, 'not found / connected at the moment')

        except socket.error:
            if email_addr is not None:
                self._client_dict.pop(email_addr)
                self._is_client_available.pop(email_addr)
            client_sock.close()
            print("ERROR IN SERVER")

    def start(self):
        """
        Start the SMTP server.
        """
        self._sock.bind((SMTP_SERVER_IP, self._port))
        self._sock.listen()
        self._sock = self._sock
        print('server is up')
        while True:
            client_sock, client_address = self._sock.accept()
            client_thread = threading.Thread(target=self._receive_email, args=(client_sock,))
            client_thread.start()

    def stop(self):
        """
        Stop the SMTP server.
        """
        self._sock.close()

    @staticmethod
    def _send_email(mailToSend: Email, files) -> str:
        """
        Send an email to the database and return the ID.

        Parameters:
        - mailToSend (Email): The email to be sent.

        Returns:
        str: The ID of the stored email.
        """

        db = DataBaseService()
        return db.store_email(mailToSend.sender, mailToSend.recipients, mailToSend.subject, mailToSend.message,
                              mailToSend.creation_date, files)

    @staticmethod
    def _save_files(files) -> list:
        db = DataBaseService()
        return db.save_files(files)


if __name__ == "__main__":
    # Create and start the SMTP server
    server = SMTPServer(SMTP_SERVER_PORT)
    server.start()
