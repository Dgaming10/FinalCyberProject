import datetime
import socket
import threading
from DataBaseServer import DataBaseService
import pickle

from Mail import Mail

POP3_SERVER_IP = socket.gethostbyname(socket.gethostname())
POP3_SERVER_PORT = 1112


class POP3Server:
    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._dbService = DataBaseService()

    def __del__(self):
        if hasattr(self, '_dbService'):
            del self._dbService

    def handle_client(self, email, client_sock):
        try:
            while True:
                cmd = client_sock.recv(1024).decode()
                print('cmd is:', cmd)
                if not cmd:
                    break

                if cmd == 'exit':
                    client_sock.close()
                    break
                elif cmd == 'recv':
                    all_mails = self._dbService.get_all_received_mails(email)
                    all_list_dict = [Mail(m.get('sender').get('email'),
                                          [rec.get('email') for rec in m.get('recipients')],
                                          m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id'))
                                     for m in all_mails]

                    all_mails_dump = pickle.dumps(all_list_dict)
                    client_sock.send(all_mails_dump)
                elif cmd == 'sent':
                    all_mails = self._dbService.get_all_sent_mails(email)
                    all_list_dict = [Mail(m.get('sender').get('email'),
                                          [rec.get('email') for rec in m.get('recipients')],
                                          m.get('subject'), m.get('message'), m.get('creation_date'), m.get('_id'))
                                     for m in all_mails]

                    all_mails_dump = pickle.dumps(all_list_dict)
                    client_sock.send(all_mails_dump)
                else:
                    mongo_mail = self._dbService.find_email_by_id(cmd)
                    single_mail_obj = Mail(mongo_mail.get('sender').get('email'),
                                           [mail.get('email') for mail in mongo_mail.get('recipients')],
                                           mongo_mail.get('subject'), mongo_mail.get('message'),
                                           mongo_mail.get('creation_date'), mongo_mail.get('_id'))
                    mongo_mail_dump = pickle.dumps(single_mail_obj)

                    client_sock.send(mongo_mail_dump)
        except socket.error as e:
            print("Socket Error:", e)
        finally:
            client_sock.close()

    def run(self):
        self._socket.bind((POP3_SERVER_IP, POP3_SERVER_PORT))
        self._socket.listen()
        print('POP3 is up')
        try:
            while True:
                client_sock, addr = self._socket.accept()
                client_email = client_sock.recv(1024).decode()
                if len(client_email) > 0 and '@' in client_email:
                    client_sock.send(b'ACK')
                    threading.Thread(target=self.handle_client, args=(client_email, client_sock,)).start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self._socket.close()


if __name__ == "__main__":
    server = POP3Server()
    server.run()
