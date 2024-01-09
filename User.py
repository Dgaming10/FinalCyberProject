import datetime
import pickle
import re
import socket
import threading
import tkinter as tk
from time import strptime, sleep
from tkinter import messagebox, ttk
from tkinter.constants import DISABLED, NORMAL

from tkcalendar import DateEntry

import DataBaseServer
from Base64 import Base64
from Mail import Mail


# FIX OPEN SOCKET AGAIN AFTER EXIT AND CONSIDER SENDING THE WHOLE MAIL AT THE BEGINNING

class User:
    def __init__(self):
        # TODO: change part of the variables from email to mail
        self._age = None
        self._first_name = None
        self._last_name = None
        self._email = None

        # Initialize GUI elements
        self.root = tk.Tk()
        self.root.title("MailUN")
        self.root.geometry("500x600")
        self.root.configure(bg="#f0f0f0")

        self._loginPage = tk.Frame(self.root)
        self._registerPage = tk.Frame(self.root)
        self._mails_frame = tk.Frame(self.root)
        self._single_mail_frame = tk.Frame(self.root)
        self._send_email_frame = tk.Frame(self.root)

        self._registration_label_register = None
        self._email_label_register = None
        self._email_entry_reg_register = None
        self._password_label_register = None
        self._password_entry_reg_register = None
        self._first_name_label_register = None
        self._first_name_entry_register = None
        self._last_name_label_register = None
        self._last_name_entry_register = None
        self._birth_date_label_register = None
        self._birth_date_entry_register = None
        self._register_button_register = None
        self._login_button1 = None
        self._email_label = None
        self._email_entry = None
        self._password_label = None
        self._password_entry = None
        self._login_button = None
        self._register_button = None
        self._send_mail_recipients_label = None
        self._send_mail_recipients_entry = None
        self._send_mail_subject_label = None
        self._send_mail_subject_entry = None
        self._send_mail_message_label = None
        self._send_mail_message_text = None
        self._send_mail_send_button = None
        self._send_mail_back_button = None
        self._mails_top_label = None
        self._login_register_button = None
        self._send_mail_scheduled_label = None
        self._send_mail_scheduled_date = None
        self._send_email_scheduled_hour = None
        self._send_email_scheduled_check_btn = None
        self._send_email_scheduled_minute = None
        self._send_email_scheduled_hour_label = None
        self._send_email_scheduled_minute_label = None

        self._transition_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._pop3_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._is_scheduled_btn = tk.IntVar()

        self._mails_top_label = tk.Label(self._mails_frame, text="MUN MAILS")
        self._mails_top_label.pack(side='top', pady=5)

        self._side_menu_frame = tk.Frame(self._mails_frame, bg="#f0f0f0")  # Add this line

        self._current_filter_state = "recv"

        self.initialize_gui()

    def initialize_gui(self):
        # Add GUI initialization logic here
        self.login_page()
        self.register_page()
        self._loginPage.pack(fill="both", expand=1)
        self.root.mainloop()

    def is_valid_password(self, password) -> bool:
        password_pattern = r"^[a-zA-Z0-9\-_\.!@#$%]{11,16}$"
        return re.match(password_pattern, password) is not None

    def is_valid_username(self, username) -> bool:
        username_pattern = r"^[a-zA-Z0-9\-_\.]{5,16}$"
        return re.match(username_pattern, username) is not None

    def is_valid_email(self, email) -> bool:
        return email.endswith('@mun.com') and self.is_valid_username(email[:email.rfind('@')])

    def login_page(self):
        self._email_label = tk.Label(self._loginPage, text="Email", bg="#f0f0f0")
        self._email_label.pack(pady=10)

        self._email_entry = tk.Entry(self._loginPage, width=30, font=("Helvetica", 12))
        self._email_entry.pack(pady=5)

        self._password_label = tk.Label(self._loginPage, text="Password:", bg="#f0f0f0")
        self._password_label.pack(pady=10)

        self._password_entry = tk.Entry(self._loginPage, show="•", width=30, font=("Helvetica", 12))
        self._password_entry.pack(pady=5)

        self._login_button = tk.Button(self._loginPage, text="Login",
                                       command=lambda: self.login(self._email_entry.get(), self._password_entry.get()),
                                       bg="#4caf50",
                                       fg="white", width=20,
                                       font=("Helvetica", 12))

        self._login_button.pack(pady=10)

        self._login_register_button = tk.Button(self._loginPage, text="Don't have an account? Register!",
                                                command=self.open_register_page)
        self._login_register_button.pack(pady=10)

    def login(self, email, password):
        # Add your login logic here
        if self.is_valid_email(email) and self.is_valid_password(password):
            messagebox.showinfo("Login", f"Logged in with email: {email}")
            db = DataBaseServer.DataBaseService()
            user_dict = db.authenticate_user(email, password)
            print(user_dict)
            if len(user_dict.keys()) == 0:
                messagebox.showerror("Login failed!", "Please try again")
            else:
                messagebox.showinfo("Successful login!", f"Hey {user_dict['first_name']}! Welcome to MailUN")
                self._transition_socket.connect(('127.0.0.1', 8080))
                print("connected to server from", self._transition_socket)
                self._loginPage.destroy()
                self._registerPage.destroy()
                self._age = user_dict['age']
                self._first_name = user_dict['first_name']
                self._last_name = user_dict['last_name']
                self._email = user_dict['email']
                self._pop3_socket.connect(('127.0.0.1', 8081))
                self._pop3_socket.send(self._email.encode())
                self._transition_socket.send(self._email.encode())
                while self._pop3_socket.recv(1024).decode() != 'ACK':
                    self._pop3_socket.send(self._email.encode())
                self.open_mails_window(None)
                receiveThread = threading.Thread(target=self.receive_mails)
                receiveThread.start()
        else:
            messagebox.showerror("Error", "Invalid email or password format")

    def register(self):
        email = self._email_entry.get()
        password = self._password_entry.get()

        if self.is_valid_email(email):
            messagebox.showinfo("Register", f"Registered with email: {email}")
            # Add your registration logic here
        else:
            messagebox.showerror("Error", "Invalid email format")

    def register_page(self):
        self._registration_label_register = tk.Label(self._registerPage, text="Registration Form",
                                                     font=("Helvetica", 16))
        self._registration_label_register.pack(pady=10)

        self._email_label_register = tk.Label(self._registerPage, text="Email (****@mun.com):")
        self._email_label_register.pack()

        self._email_entry_reg_register = tk.Entry(self._registerPage, width=30)
        self._email_entry_reg_register.pack()

        self._password_label_register = tk.Label(self._registerPage, text="Password:")
        self._password_label_register.pack()

        self._password_entry_reg_register = tk.Entry(self._registerPage, show="•", width=30)
        self._password_entry_reg_register.pack()

        self._first_name_label_register = tk.Label(self._registerPage, text="First Name:")
        self._first_name_label_register.pack()

        self._first_name_entry_register = tk.Entry(self._registerPage, width=30)
        self._first_name_entry_register.pack()

        self._last_name_label_register = tk.Label(self._registerPage, text="Last Name:")
        self._last_name_label_register.pack()

        self._last_name_entry_register = tk.Entry(self._registerPage, width=30)
        self._last_name_entry_register.pack()

        self._birth_date_label_register = tk.Label(self._registerPage, text="Birth Date (DD-MM-YYYY):")
        self._birth_date_label_register.pack()

        self._birth_date_entry_register = tk.Entry(self._registerPage, width=30)
        self._birth_date_entry_register.pack()

        self._register_button_register = tk.Button(self._registerPage, text="Submit", command=self.register,
                                                   bg="#4caf50", fg="white",
                                                   width=20,
                                                   font=("Helvetica", 12))
        self._register_button_register.pack(pady=10)

        self._login_button1 = tk.Button(self._registerPage, text="Login", command=self.open_loginPage, bg="#2196F3",
                                        fg="white",
                                        width=20,
                                        font=("Helvetica", 13))

        self._login_button1.pack(pady=10)

    def open_loginPage(self):
        self._loginPage.pack(fill='both', expand=1)
        self._registerPage.forget()

    def open_send_mail_window(self):
        self._mails_frame.pack_forget()
        for widget in self._send_email_frame.winfo_children():
            widget.destroy()
        # Recipients
        self._send_mail_recipients_label = tk.Label(self._send_email_frame, text="Recipients:")
        self._send_mail_recipients_label.pack()

        self._send_mail_recipients_entry = tk.Entry(self._send_email_frame)
        self._send_mail_recipients_entry.pack(fill="x")

        # Subject
        self._send_mail_subject_label = tk.Label(self._send_email_frame, text="Subject:")
        self._send_mail_subject_label.pack()

        self._send_mail_subject_entry = tk.Entry(self._send_email_frame)
        self._send_mail_subject_entry.pack(fill="x")

        # Message
        self._send_mail_message_label = tk.Label(self._send_email_frame, text="Message:")
        self._send_mail_message_label.pack()

        self._send_mail_message_text = tk.Text(self._send_email_frame, height=10, width=40)
        self._send_mail_message_text.pack()

        self._send_mail_scheduled_label = tk.Label(self._send_email_frame, text="Message:")
        self._send_mail_scheduled_label.pack()

        self._send_mail_scheduled_date = DateEntry(self._send_email_frame, width=12, background='darkblue',
                                                   foreground='white', borderwidth=2)
        self._send_mail_scheduled_date.pack(pady=10)

        self._send_email_scheduled_hour = ttk.Spinbox(
            self._send_email_frame,
            from_=0,
            to=23,
            wrap=True,
            width=3
        )
        self._send_email_scheduled_hour.set("0")
        self._send_email_scheduled_hour.place(relx=0.6, rely=0.8, anchor=tk.CENTER)

        self._send_email_scheduled_hour_label = tk.Label(self._send_email_frame, text="Hours:")
        self._send_email_scheduled_hour_label.place(relx=0.6, rely=0.75, anchor=tk.CENTER)

        self._send_email_scheduled_minute = ttk.Spinbox(
            self._send_email_frame,
            from_=0,
            to=59,
            wrap=True,
            width=3
        )
        self._send_email_scheduled_minute.set("0")
        self._send_email_scheduled_minute.place(relx=0.7, rely=0.8, anchor=tk.CENTER)

        self._send_email_scheduled_minute_label = tk.Label(self._send_email_frame, text="Minutes:")
        self._send_email_scheduled_minute_label.place(relx=0.7, rely=0.75, anchor=tk.CENTER)

        self._send_email_scheduled_check_btn = tk.Checkbutton(
            self._send_email_frame, text='Enable Scheduled Email', variable=self._is_scheduled_btn,
            onvalue=True, offvalue=False)
        self._send_email_scheduled_check_btn.place(relx=0.3, rely=0.8, anchor=tk.CENTER)

        self._send_mail_send_button = tk.Button(self._send_email_frame, text="Send", command=self.send_email)
        self._send_mail_send_button.pack()

        self._send_mail_back_button = tk.Button(self._send_email_frame, text="Go Back", command=self.open_mails_window)
        self._send_mail_back_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

        self._send_email_frame.pack(fill='both', expand=1)

    def validate_before_send(self):
        hour = self._send_email_scheduled_hour.get()
        min = self._send_email_scheduled_minute.get()
        if self._send_mail_recipients_entry.get() == '':
            messagebox.showerror("Error", "Please enter a one or more recipient")
            return False
        elif self._is_scheduled_btn.get() == 1:
            try:
                int(hour)
                int(min)
                if not (0 <= int(hour) < 24 and 0 <= int(min) < 60):
                    int("saf")
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid time")
                return False

        return True

    def send_email(self):

        validation_ans = self.validate_before_send()
        print("VALIDATION IS :", validation_ans, int(self._send_email_scheduled_minute.get()),
              int(self._send_email_scheduled_hour.get()))

        if validation_ans is False:
            return
        emails: str = self._send_mail_recipients_entry.get()
        realEmails = [Base64.Encrypt(i) for i in emails.split(',') if i != ""]
        # TODO: check if only set(realEmails) will have a different impact
        realEmails = list(set(realEmails))
        print(f"mail sent from {self._email} to: {realEmails}")
        # db = DataBaseServer.DataBaseService()
        # recipients = [DataBaseServer.mongo_obj_to_User(db.email_to_mongo_obj(email)) for email in realEmails]
        if self._is_scheduled_btn.get() == 1:
            new_datetime = datetime.datetime(year=self._send_mail_scheduled_date.get_date().year,
                                             month=self._send_mail_scheduled_date.get_date().month,
                                             day=self._send_mail_scheduled_date.get_date().day,
                                             hour=int(self._send_email_scheduled_hour.get()),
                                             minute=int(self._send_email_scheduled_minute.get()))
            sendEmail: Mail = Mail(Base64.Encrypt(self._email), realEmails, Base64.Encrypt(self._send_mail_subject_entry.get()),
                                   Base64.Encrypt(self._send_mail_message_text.get("1.0", 'end-1c')),
                                   new_datetime)
        else:
            sendEmail: Mail = Mail(Base64.Encrypt(self._email), realEmails,
                                   Base64.Encrypt(self._send_mail_subject_entry.get()),
                                   Base64.Encrypt(self._send_mail_message_text.get("1.0", 'end-1c')))

        sendEmail_dumps = pickle.dumps(sendEmail)
        sentBytes = self._transition_socket.send(sendEmail_dumps)
        while sentBytes <= 0:
            sentBytes = self._transition_socket.send(sendEmail_dumps)

        print("EMAIL SENT!")

        #anti spam
        self._send_mail_send_button.configure(state='disabled')
        self._send_email_frame.after(2000, self.enable_send_button)

    def enable_send_button(self):
        self._send_mail_send_button.configure(state='normal')


    def open_register_page(self):
        self._registerPage.pack(fill='both', expand=1)
        self._loginPage.forget()

    def open_single_mail_window(self, mail):
        for widget in self._single_mail_frame.winfo_children():
            widget.destroy()
        # change to set mail from DB, use Mail class
        self._pop3_socket.send(str(mail.mongo_id).encode())
        mail_received_obj = pickle.loads(self._pop3_socket.recv(1024))
        single_mail_frame_label = tk.Label(self._single_mail_frame, text=Base64.Decrypt(mail_received_obj.message), bg="lightgray",
                                           relief="raised")

        single_mail_frame_label.pack(fill=tk.X)
        single_mail_frame_label.bind("<Button-1>", self.open_mails_window)
        self._mails_frame.pack_forget()
        self._single_mail_frame.pack(fill='both', expand=1)

    def open_mails_window(self, e=None):
        for widget in self._mails_frame.winfo_children():
            widget.destroy()

        def _load_mails(filter_type) -> [Mail]:
            for inner_widget in self._mails_frame.winfo_children():
                if inner_widget.winfo_class() == 'Label':
                    inner_widget.destroy()

            if filter_type == 'sent':
                self._pop3_socket.send(b'sent')

            else:
                self._pop3_socket.send(b'recv')

            mails: [Mail] = pickle.loads(self._pop3_socket.recv(1024))
            labels = [f"{mail.sender} -> {Base64.Decrypt(mail.subject)} | {mail.creation_date}"
                      for mail in mails]

            for label_text, mail in zip(labels, mails):
                label = tk.Label(self._mails_frame, text=label_text, bg="lightgray",
                                 relief="raised", cursor="hand2")
                label.bind("<Button-1>", lambda event, mail2=mail: self.open_single_mail_window(mail2))
                label.pack(fill=tk.X)
            self._mails_frame.pack(fill='both', expand=1)
            self._current_filter_state = filter_type

        self._side_menu_frame = tk.Frame(self._mails_frame, bg="#f0f0f0")
        # Packing the side menu frame
        self._side_menu_frame.pack(side='right', fill='y', padx=10, pady=10)

        # Received button
        received_button = tk.Button(self._side_menu_frame, text="Received",
                                    command=lambda: _load_mails('recv'))
        received_button.pack(fill='x', pady=5)

        # Sent button
        sent_button = tk.Button(self._side_menu_frame, text="Sent",
                                command=lambda: _load_mails('sent'))
        sent_button.pack(fill='x', pady=5)

        # Send mail button (assuming you want it inside the mails frame)
        send_mail_button = tk.Button(self._mails_frame, text="Send Mail",
                                     command=self.open_send_mail_window)
        send_mail_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

        # Pack the main mails frame

        self._single_mail_frame.pack_forget()
        self._send_email_frame.pack_forget()

        _load_mails('recv')

        # Implement or add placeholders for these methods

    def run(self):
        # Start the GUI event loop
        self.root.mainloop()

    def receive_mails(self):
        while True:
            code = self._transition_socket.recv(1024)
            print("CODE IS: ", code)
            mailReceived: Mail = pickle.loads(code)
            print("RECEIVED", mailReceived, mailReceived.recipients, mailReceived.sender)
            print("IM", self._email)
            self.root.after(0, lambda: self.update_gui_with_new_mail(mailReceived))

    def update_gui_with_new_mail(self, mail):
        # Update the GUI to reflect the new mail
        # For example, adding a new label for the mail
        if self._current_filter_state == "sent":
            return
        label = tk.Label(self._mails_frame,
                         text=f"{mail.sender} -> {Base64.Decrypt(mail.subject)} | {mail.creation_date}", bg="lightgray",
                         relief="raised",
                         cursor="hand2")

        label.bind("<Button-1>", lambda event, mail2=mail: self.open_single_mail_window(mail2))
        label.pack(fill=tk.X)


# Example of how to use the User class
if __name__ == "__main__":
    user = User()
