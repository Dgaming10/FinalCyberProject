import datetime
import socket
import threading
from DataBaseServer import DataBaseService
import pickle

from Mail import Mail


class POP3Server:
    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._dbService = DataBaseService()

    def handle_client(self, email, client_sock):
        while True:
            try:
                cmd = client_sock.recv(1024).decode()
                print('cmd is:', cmd)
                if cmd == 'exit':
                    client_sock.close()
                    break
                elif cmd == 'recv':
                    all_mails = self._dbService.get_all_received_mails(
                        email)  # {'sender_email': m.get('sender').get('email'), 'subject': m.get('subject'),
                    # 'creation_date': m.get('creation_date'), 'id': m.get('_id')}

                    all_list_dict = [Mail(m.get('sender').get('email'),
                                          [rec.get('email') for rec in m.get('recipients')], m.get('subject'),
                                          m.get('message'), m.get('creation_date'), m.get('_id')) for m in all_mails]
                    print(all_list_dict[0].mongo_id)
                    all_mails_dump = pickle.dumps(all_list_dict)
                    client_sock.send(all_mails_dump)
                elif cmd == 'sent':
                    all_mails = self._dbService.get_all_sent_mails(
                        email)  # {'sender_email': m.get('sender').get('email'), 'subject': m.get('subject'),
                    # 'creation_date': m.get('creation_date'), 'id': m.get('_id')}
                    all_list_dict = [Mail(m.get('sender').get('email'),
                                          [rec.get('email') for rec in m.get('recipients')], m.get('subject'),
                                          m.get('message'), m.get('creation_date'), m.get('_id')) for m in all_mails]
                    print(all_list_dict[0].mongo_id)
                    all_mails_dump = pickle.dumps(all_list_dict)
                    client_sock.send(all_mails_dump)
                else:
                    mongo_mail = self._dbService.find_email_by_id(cmd)
                    single_mail_obj: Mail = Mail(mongo_mail.get('sender').get('email'),
                                                 [mail.get('email') for mail in mongo_mail.get('recipients')],
                                                 mongo_mail.get('subject'), mongo_mail.get('message'),
                                                 mongo_mail.get('creation_date'),
                                                 mongo_mail.get('_id'))
                    mongo_mail_dump = pickle.dumps(single_mail_obj)

                    client_sock.send(mongo_mail_dump)
            except socket.error:
                print("ERROR")
                client_sock.close()
                break

    def run(self):
        self._socket.bind(('127.0.0.1', 8081))
        self._socket.listen()
        print('pop3 is up')
        while True:
            client_sock, addr = self._socket.accept()
            client_email = client_sock.recv(1024).decode()
            if len(client_email) > 0 and '@' in client_email:
                client_sock.send(b'ACK')
                threading.Thread(target=self.handle_client, args=(client_email, client_sock,)).start()


if __name__ == "__main__":
    server2 = POP3Server()
    server2.run()
