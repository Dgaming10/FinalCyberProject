import datetime
import pickle
import socket
from DataBaseServer import DataBaseService
import threading
import json
from Mail import Mail


class SMTPServer:
    def __init__(self, port):
        self._port = port
        self._sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client_dict: dict = {}

    def _receive_email(self, client_sock: socket.socket):
        try:
            mail_addr = client_sock.recv(1024).decode()
            self._client_dict[mail_addr] = client_sock
            while True:
                while True:
                    sentMail: Mail = pickle.loads(client_sock.recv(1024))
                    if isinstance(sentMail, Mail):
                        print("BREAKING")
                        break

                print('RECEIVED', sentMail.recipients, sentMail.message, sentMail.subject, sentMail.creation_date,
                      sentMail.sender)
                for email in sentMail.recipients:
                    try:
                        new_id: str = self._send_email(sentMail)
                        email_sock: socket.socket = self._client_dict[email]
                        sentMail.mongo_id = new_id
                        email_sock.send(pickle.dumps(sentMail))
                        print("SENT BY SOCKET TO", email)
                    except KeyError:
                        print(email, 'not found / connected at the moment')



        except socket.error:

            print("ERROR IN SERVER")

    def start(self):
        self._sock.bind(('127.0.0.1', self._port))
        self._sock.listen()
        self._sock = self._sock
        print('server is up')
        while True:
            client_sock, client_address = self._sock.accept()
            client_thread = threading.Thread(target=self._receive_email, args=(client_sock,))
            client_thread.start()

    def stop(self):
        self._sock.close()

    def _send_email(self, mailToSend: Mail) -> str:
        db = DataBaseService()
        return db.store_email(mailToSend.sender, mailToSend.recipients, mailToSend.subject, mailToSend.message,
                              mailToSend.creation_date)


if __name__ == "__main__":
    server = SMTPServer(8080)
    server.start()
