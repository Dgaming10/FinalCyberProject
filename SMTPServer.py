import pickle
import socket
import threading
import globals_module

from Base64 import Base64
from DataBaseServer import DataBaseService
from File import File
from Mail import Mail

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

    def _receive_email(self, client_sock: socket.socket):
        """
        Receive and process an email from a client.

        Parameters:
        - client_sock (socket.socket): The socket of the connected client.
        """
        try:
            mail_addr = client_sock.recv(1024).decode()
            self._client_dict[mail_addr] = client_sock
            files = []
            while True:
                while True:
                    files.clear()
                    client_msg = client_sock.recv(5)
                    if client_msg == b'CLOSE':
                        client_sock.send(b'-1')
                        continue

                    files_list_length = int.from_bytes(client_msg, byteorder='big')
                    print(files_list_length)
                    client_sock.send(b'ACK')
                    m = client_sock.recv(files_list_length)
                    print(len(m))
                    files_list: [File] = pickle.loads(m)
                    client_sock.send(b'ACK')
                    for f in files_list:
                        print(f.name, f.extension, f.content)
                        files.append((f.name, f.extension, f.content))

                    # for tup in files:
                    #     file = open(f'fileReceived/{tup[0]}.{tup[1]}', 'wb')
                    #     file.write(tup[2])
                    #     file.close()

                    pickle_mail_len = int.from_bytes(client_sock.recv(4), byteorder='big')
                    client_sock.send(b'ACK')
                    sentMail: Mail = pickle.loads(client_sock.recv(pickle_mail_len))
                    if isinstance(sentMail, Mail):
                        print("BREAKING")
                        break

                sentMail = Mail(Base64.Decrypt(sentMail.sender), [Base64.Decrypt(i) for i in sentMail.recipients],
                                sentMail.subject, sentMail.message,
                                sentMail.creation_date)

                print('RECEIVED', sentMail.recipients, sentMail.message, sentMail.subject, sentMail.creation_date,
                      sentMail.sender)
                if files:
                    files = SMTPServer._save_files(files)

                for email in sentMail.recipients:
                    try:
                        print("SENT:", files)
                        new_id: str = SMTPServer._send_email(sentMail, files)
                        email_sock: socket.socket = self._client_dict[email]
                        sentMail.mongo_id = new_id
                        sentMail.files_ids = files

                        email_sock.send(pickle.dumps(sentMail))
                        print("SENT BY SOCKET TO", email)
                    except KeyError:
                        print(email, 'not found / connected at the moment')

        except socket.error:
            self._client_dict.pop(client_sock)
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
    def _send_email(mailToSend: Mail, files) -> str:
        """
        Send an email to the database and return the ID.

        Parameters:
        - mailToSend (Mail): The email to be sent.

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
