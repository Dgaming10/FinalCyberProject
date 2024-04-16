import datetime
import pickle
import re
import socket
import threading
from random import randint
from time import sleep
import tkinter as tk
from os import path
from tkinter import messagebox, ttk, filedialog
from tkcalendar import DateEntry

import globals_module
from Base64 import Base64
from File import File
from Email import Email

SMTP_SERVER_IP = '192.168.0.181'
POP3_SERVER_IP = '192.168.0.181'

SMTP_SERVER_PORT = 1111
POP3_SERVER_PORT = 1112


# FIX OPEN SOCKET AGAIN AFTER EXIT AND CONSIDER SENDING THE WHOLE MAIL AT THE BEGINNING

class User:
    """
    Class representing a user in the MailUN application.

    Attributes:
    - _age (int): The age of the user.
    - _first_name (str): The first name of the user.
    - _last_name (str): The last name of the user.
    - _email (str): The email address of the user.
    - root (tk.Tk): The main Tkinter window.
    - _loginPage (tk.Frame): The login page frame.
    - _registerPage (tk.Frame): The registration page frame.
    - _mails_frame (tk.Frame): The frame for displaying mails.
    - _single_mail_frame (tk.Frame): The frame for displaying a single mail.
    - _send_email_frame (tk.Frame): The frame for sending emails.
    - _registration_label_register (tk.Label): Label for registration form.
    - ... (Other GUI elements)

    Methods:
    - __init__: Initialize the User instance.
    - initialize_gui: Initialize the GUI elements.
    - is_valid_password: Check if a password is valid.
    - is_valid_username: Check if a username is valid.
    - is_valid_email: Check if an email is valid.
    - login_page: Display the login page.
    - login: Handle the login process.
    - register: Handle the registration process.
    - register_page: Display the registration page.
    - open_loginPage: Open the login page.
    - select_file: Open a file dialog to select a file.
    - open_send_email_window: Open the window for sending emails.
    - validate_before_send: Validate input before sending an email.
    - send_email: Send an email.
    - enable_send_button: Enable the send email button after a delay.
    - open_register_page: Open the registration page.
    - open_single_email_window: Open the window for a single email.
    - open_emails_window: Open the window for displaying emails.
    - run: Start the GUI event loop.
    - receive_emails: Receive emails in a separate thread.
    - update_gui_with_new_email: Update the GUI with a new email.
    """

    def __init__(self):
        """
        Initialize the User instance.
        """
        self._files_list = []
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
        self._emails_frame = tk.Frame(self.root)
        self._single_email_frame = tk.Frame(self.root)
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
        self._send_email_recipients_label = None
        self._send_email_recipients_entry = None
        self._send_email_subject_label = None
        self._send_email_subject_entry = None
        self._send_email_message_label = None
        self._send_email_message_text = None
        self._send_email_send_button = None
        self._send_email_back_button = None
        self._emails_top_label = None
        self._login_register_button = None
        self._send_email_scheduled_label = None
        self._send_email_scheduled_date = None
        self._send_email_scheduled_hour = None
        self._send_email_scheduled_check_btn = None
        self._send_email_scheduled_minute = None
        self._send_email_scheduled_hour_label = None
        self._send_email_scheduled_minute_label = None
        self._send_email_open_file_button = None
        self._single_email_save_button = None
        self._single_email_delete_button = None

        self._transition_socket: socket = None
        self._pop3_socket: socket = None
        self._is_scheduled_btn = tk.IntVar()
        self._receive_thread: threading.Thread = None
        self._run_receive_thread = False

        self._emails_top_label = tk.Label(self._emails_frame, text="MUN MAILS")
        self._emails_top_label.pack(side='top', pady=5)

        self._side_menu_frame = tk.Frame(self._emails_frame, bg="#f0f0f0")  # Add this line

        self._current_filter_state = ["recv", False]

        self.initialize_gui()

    def initialize_gui(self):
        """
        Initialize the GUI elements.
        """

        # Add GUI initialization logic here
        self.login_page()
        self.register_page()
        self._loginPage.pack(fill="both", expand=1)
        self.root.mainloop()

    @staticmethod
    def is_valid_password(password) -> bool:
        """
        Check if a password is valid.

        Parameters:
        - password (str): The password to be validated.

        Returns:
        bool: True if the password is valid, False otherwise.
        """
        password_pattern = r"^[a-zA-Z0-9\-_\.!@#$%]{11,16}$"
        return re.match(password_pattern, password) is not None

    @staticmethod
    def is_valid_username(username) -> bool:
        """
        Check if a username is valid.

        Parameters:
        - username (str): The username to be validated.

        Returns:
        bool: True if the username is valid, False otherwise.
        """
        username_pattern = r"^[a-zA-Z0-9\-_\.]{5,16}$"
        return re.match(username_pattern, username) is not None

    @staticmethod
    def is_valid_email(email) -> bool:
        """
        Check if an email is valid.

        Parameters:
        - email (str): The email to be validated.

        Returns:
        bool: True if the email is valid, False otherwise.
        """
        return email.endswith('@mun.com') and User.is_valid_username(email[:email.rfind('@')])

    def login_page(self):
        """
        Display the login page.
        """
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
        """
        Handle the login process.

        Parameters:
        - email (str): The user's email.
        - password (str): The user's password.
        """
        # Add your login logic here
        if User.is_valid_email(email) and User.is_valid_password(password):
            self._email = Base64.Encrypt(email)
            self.start_pop3_connection()
            messagebox.showinfo("Login", f"Logged in with email: {email}")
            self._pop3_socket.send(b'login')
            self._pop3_socket.recv(3)
            login_tuple_pickle = b'abcd' + pickle.dumps((Base64.Encrypt(email), Base64.Encrypt(password)))
            self._pop3_socket.send(len(login_tuple_pickle).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(3)
            self._pop3_socket.send(login_tuple_pickle)
            len_dict = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(b'ACK')
            user_dict = pickle.loads(self._pop3_socket.recv(len_dict)[4:])
            print(user_dict)
            if len(user_dict.keys()) == 0:
                messagebox.showerror("Login failed!", "Please try again")
                self._pop3_socket.close()
            else:
                messagebox.showinfo("Successful login!",
                                    f"Hey {Base64.Decrypt(user_dict['first_name'])}! Welcome to MailUN")

                self._loginPage.destroy()
                self._registerPage.destroy()
                self._age = user_dict['age']
                self._first_name = user_dict['first_name']
                self._last_name = user_dict['last_name']
                self._email = user_dict['email']
                self.start_smtp_connection()
                print("connected to server from", self._transition_socket)
                self.restart_thread()
        else:
            messagebox.showerror("Error", "Invalid email or password format")

    def register(self):
        """
        Handle the registration process.
        """
        # TODO - add register function
        email = self._email_entry.get()
        password = self._password_entry.get()

        if self.is_valid_email(email):
            messagebox.showinfo("Register", f"Registered with email: {email}")
            # Add your registration logic here
        else:
            messagebox.showerror("Error", "Invalid email format")

    def register_page(self):
        """
        Display the registration page.
        """
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
        """
        Open the login page.
        """
        self._loginPage.pack(fill='both', expand=1)
        self._registerPage.forget()

    def select_files(self):
        filename = tk.filedialog.askopenfilenames(title="Select files",
                                                  filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        self._files_list = filename

    def open_send_email_window(self):
        """
        Open the window for sending emails.
        """
        self._current_filter_state[1] = True
        self._emails_frame.pack_forget()
        for widget in self._send_email_frame.winfo_children():
            widget.destroy()
        # Recipients
        self._send_email_recipients_label = tk.Label(self._send_email_frame, text="Recipients:")
        self._send_email_recipients_label.pack()

        self._send_email_recipients_entry = tk.Entry(self._send_email_frame)
        self._send_email_recipients_entry.pack(fill="x")

        # Subject
        self._send_email_subject_label = tk.Label(self._send_email_frame, text="Subject:")
        self._send_email_subject_label.pack()

        self._send_email_subject_entry = tk.Entry(self._send_email_frame)
        self._send_email_subject_entry.pack(fill="x")

        # Message
        self._send_email_message_label = tk.Label(self._send_email_frame, text="Message:")
        self._send_email_message_label.pack()

        self._send_email_message_text = tk.Text(self._send_email_frame, height=10, width=40)
        self._send_email_message_text.pack()

        self._send_email_scheduled_label = tk.Label(self._send_email_frame, text="Message:")
        self._send_email_scheduled_label.pack()

        self._send_email_scheduled_date = DateEntry(self._send_email_frame, width=12, background='darkblue',
                                                    foreground='white', borderwidth=2)
        self._send_email_scheduled_date.pack(pady=10)

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

        self._send_email_send_button = tk.Button(self._send_email_frame, text="Send", command=self.send_email)
        self._send_email_send_button.pack()

        self._send_email_open_file_button = tk.Button(self._send_email_frame, text="Choose files",
                                                      command=self.select_files)
        self._send_email_open_file_button.place(relx=0.5, rely=0.65, anchor=tk.CENTER)
        self._send_email_back_button = tk.Button(self._send_email_frame, text="Go Back",
                                                 command=self.restart_thread)
        self._send_email_back_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

        self._send_email_frame.pack(fill='both', expand=1)

    def validate_before_send(self):
        """
        Validate input before sending an email.

        Returns:
        bool: True if the input is valid, False otherwise.
        """
        hour = self._send_email_scheduled_hour.get()
        minutes = self._send_email_scheduled_minute.get()
        if self._send_email_recipients_entry.get() == '':
            messagebox.showerror("Error", "Please enter a one or more recipient")
            return False
        elif self._is_scheduled_btn.get() == 1:
            try:
                int(hour)
                int(minutes)
                if not (0 <= int(hour) < 24 and 0 <= int(minutes) < 60):
                    int("saf")
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid time")
                return False

        return True

    def restart_thread(self):
        try:
            if self._transition_socket is None:
                return
            self._transition_socket.send(b'OPEN')
            print('sent OPEN to SMTP')
            self._receive_thread = threading.Thread(target=self.receive_emails)
            self._run_receive_thread = True
            self._receive_thread.start()
            self.open_emails_window(None)
        except (threading.ThreadError, socket.error):
            print('-------------------- error in restarting thread -------------------------')
            messagebox.showerror("Error occurred!", "Place - restarting thread")

    def start_pop3_connection(self):
        try:
            self._pop3_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._pop3_socket.connect((POP3_SERVER_IP, POP3_SERVER_PORT))
            self._pop3_socket.send(self._email.encode())
            self._pop3_socket.recv(3)
        except socket.error:
            messagebox.showerror("Error occurred!", "Place - connecting to the pop3 server")
            try:
                self._pop3_socket.close()
            finally:
                self.close_program()

    def start_smtp_connection(self):
        try:
            self._transition_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._transition_socket.connect((SMTP_SERVER_IP, SMTP_SERVER_PORT))
            self._transition_socket.send(self._email.encode())
            self._transition_socket.recv(3)
        except socket.error:
            messagebox.showerror("Error occurred!", "Place - connecting to the smtp server")
            try:
                self._transition_socket.close()
            finally:
                self.close_program()

    def close_program(self):
        try:
            if self._pop3_socket is not None:
                self._pop3_socket.close()
        finally:
            try:
                if self._transition_socket is not None:
                    self._transition_socket.close()
            finally:
                self._pop3_socket = None
                self._transition_socket = None
                self.root.destroy()

    def send_email(self):
        """
        Send an email.
        """
        validation_ans = self.validate_before_send()
        print("VALIDATION IS :", validation_ans, int(self._send_email_scheduled_minute.get()),
              int(self._send_email_scheduled_hour.get()))

        if validation_ans is False:
            return

        print('is alive?', self._receive_thread.is_alive())
        emails: str = self._send_email_recipients_entry.get()
        realEmails = [Base64.Encrypt(i) for i in emails.split(',') if i != ""]
        # TODO: check if only set(realEmails) will have a different impact
        realEmails = list(set(realEmails))
        print(f"mail sent from {self._email} to: {realEmails}")
        # db = DataBaseServer.DataBaseService()
        # recipients = [DataBaseServer.mongo_obj_to_User(db.email_to_mongo_obj(email)) for email in realEmails]
        if self._is_scheduled_btn.get() == 1:
            new_datetime = datetime.datetime(year=self._send_email_scheduled_date.get_date().year,
                                             month=self._send_email_scheduled_date.get_date().month,
                                             day=self._send_email_scheduled_date.get_date().day,
                                             hour=int(self._send_email_scheduled_hour.get()),
                                             minute=int(self._send_email_scheduled_minute.get()))
            sendEmail: Email = Email(self._email, realEmails,
                                     Base64.Encrypt(self._send_email_subject_entry.get()),
                                     Base64.Encrypt(self._send_email_message_text.get("1.0", 'end-1c')),
                                     new_datetime)
        else:
            sendEmail: Email = Email(self._email, realEmails,
                                     Base64.Encrypt(self._send_email_subject_entry.get()),
                                     Base64.Encrypt(self._send_email_message_text.get("1.0", 'end-1c')), )

        if self._is_scheduled_btn.get() != 1:
            sendEmail.update_creation_date()
        print('sent email id:', id(sendEmail))
        file_object_list = []
        for i in range(len(self._files_list)):
            file_path_name, file_path_ex = path.splitext(path.basename(self._files_list[i]))
            file_path_ex = file_path_ex[1:]
            if len(file_path_name) > globals_module.FILE_NAME_LIMIT:
                file_path_name = file_path_name[:globals_module.FILE_NAME_LIMIT]

            if len(file_path_ex) > globals_module.FILE_EXTENSION_LIMIT:
                file_path_ex = file_path_ex[:globals_module.FILE_EXTENSION_LIMIT]

            current_file = open(self._files_list[i], 'rb')
            current_file_content = current_file.read()
            current_file.close()

            file_object_list.append(File(Base64.Encrypt(file_path_name), Base64.Encrypt(file_path_ex),
                                         current_file_content[::-1]))

        print(file_object_list)
        try:

            if self._receive_thread.is_alive() is True:
                self._transition_socket.send(b'CLSE')
                print('sent CLSE to SMTP')
                self._run_receive_thread = False
                self._receive_thread.join()

            sendEmail_dumps = pickle.dumps(sendEmail)
            files_list_dumps = b'abcd' + pickle.dumps(file_object_list)
            self._transition_socket.send(len(files_list_dumps).to_bytes(4, byteorder='big'))
            print('len of files_list_dumP:', len(files_list_dumps))
            self._transition_socket.recv(3)
            print('sent:', self._transition_socket.send(files_list_dumps))
            self._transition_socket.recv(3)
            self._transition_socket.send(len(sendEmail_dumps).to_bytes(4, byteorder='big'))
            print('received', self._transition_socket.recv(3), 'from SMTP', len(sendEmail_dumps))

            sentBytes = self._transition_socket.send(sendEmail_dumps)
            while sentBytes <= 0:
                print('got in some loop')
                sentBytes = self._transition_socket.send(sendEmail_dumps)
            self._transition_socket.recv(3)

        except (socket.error, pickle.PickleError) as e:
            print('----------------------- error in sending email --------------------', e)
            messagebox.showerror("Error occurred!", "Place - sending email")
            self._transition_socket.close()
            if self._receive_thread.is_alive() is True:
                self._receive_thread.join()

            self.start_smtp_connection()
            self.restart_thread()
            return

        print("EMAIL SENT! ", sentBytes)

        # anti spam
        self._send_email_send_button.configure(state='disabled')
        self._send_email_frame.after(2000, lambda: self._send_email_send_button.configure(state='normal'))

    def open_register_page(self):
        """
        Open the registration page.
        """
        self._registerPage.pack(fill='both', expand=1)
        self._loginPage.forget()

    @staticmethod
    def saveEmail(email: Email):
        file_to_save = tk.filedialog.asksaveasfile(defaultextension='.txt', filetypes=[("Text file", ".txt")])
        files_names = "None"
        print('FILES INFO', email.files_info)
        if email.files_info:
            files_names = ", ".join(f'{tup[0]}.{tup[1]}' for tup in email.files_info)
        file_content = (
            f'Date:{email.creation_date}\nFrom:{Base64.Decrypt(email.sender)}\n'
            f'To:{[Base64.Decrypt(rec) for rec in email.recipients]}\n'
            f'Subject:{Base64.Decrypt(email.subject)}\n'
            f'Message:{Base64.Decrypt(email.message)}\n'
            f'Files:{files_names}')
        if not file_to_save:
            return
        file_to_save.write(file_content)
        file_to_save.close()

    def save_file(self, file_info):
        print('file_info:', file_info)
        file_path = filedialog.asksaveasfilename(initialfile=f'{file_info[1]}.{file_info[2]}',
                                                 defaultextension=f'.{file_info[2]}',
                                                 filetypes=[("All files", "*.*")])
        if file_path:
            self._pop3_socket.send(b'file_con')
            self._pop3_socket.recv(3)
            self._pop3_socket.send(str(file_info[0]).encode())
            file_content_length = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(b'ACK')
            file_content = self._pop3_socket.recv(file_content_length)
            selected_file = open(file_path, 'wb')
            selected_file.write(file_content[::-1])
            selected_file.close()
            print("SAVED!!!!!")

    def delete_email(self, email_obj):
        self._pop3_socket.send(b'delete')
        self._pop3_socket.recv(3)
        email_tup_dumps = pickle.dumps((email_obj.mongo_id, email_obj.sender))
        self._pop3_socket.send(len(email_tup_dumps).to_bytes(4, byteorder='big'))
        self._pop3_socket.recv(3)
        self._pop3_socket.send(email_tup_dumps)
        self._pop3_socket.recv(3)
        messagebox.showinfo("Email got deleted!")
        self.open_emails_window()

    def open_single_email_window(self, email):
        # TODO -> check the thing with having both a mail and a mail_received_obj objects.
        """
        Open the window for a single mail.

        Parameters:
        - mail: The mail object.
        """

        self._current_filter_state[1] = True
        for widget in self._single_email_frame.winfo_children():
            widget.destroy()
        # change to set mail from DB, use Email class
        try:
            self._pop3_socket.send(Base64.Encrypt(str(email.mongo_id)).encode())
            files_received_obj_length = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(b'ACK')
            files_received_obj = pickle.loads(self._pop3_socket.recv(files_received_obj_length)[4:])
        except (socket.error, pickle.PickleError) as e:
            print('-------------------- single email error -----------------------', e)
            messagebox.showerror("Error occurred!", "Place - getting single email")
            self._pop3_socket.close()
            self.start_pop3_connection()
            self.open_emails_window(None)
            return

        single_email_frame_label = tk.Label(self._single_email_frame, text=Base64.Decrypt(email.message),
                                            bg="lightgray",
                                            relief="raised")

        single_email_frame_label.pack(fill=tk.X)
        single_email_frame_label.bind("<Button-1>", self.open_emails_window)

        elements_list = [f'{tup[1]}.{tup[2]}' for tup in files_received_obj]
        print(email.files_info)
        print('elements:', elements_list)
        cols = 2

        grid_frame = tk.Frame(self._single_email_frame)
        grid_frame.pack(fill='both', expand=1)
        email.files_info = []
        # Create buttons and place them in a grid
        for i, element in enumerate(elements_list):
            print("current enum:", i, element)
            button = tk.Button(grid_frame, text=element,
                               command=lambda index=i: self.save_file(files_received_obj[index]))
            row, col = divmod(i, cols)
            button.grid(row=row, column=col, padx=5, pady=5)
            email.files_info.append((files_received_obj[i][1], files_received_obj[i][2]))
        # Create and pack the save button
        self._single_email_save_button = tk.Button(self._single_email_frame, text="Save email",
                                                   command=lambda: User.saveEmail(email))
        self._single_email_save_button.pack(side=tk.BOTTOM, pady=10)

        self._single_email_delete_button = tk.Button(self._single_email_frame, text="Delete email",
                                                     command=lambda: self.delete_email(email))
        self._single_email_delete_button.pack(side=tk.BOTTOM, pady=10)

        self._emails_frame.pack_forget()
        self._single_email_frame.pack(fill='both', expand=1)

    def open_emails_window(self, e=None):
        """
        Open the window for displaying mails.

        Parameters:
        - e: An optional event parameter.
        """

        print('received ACK from the SMTPServer')

        print('current:', self._current_filter_state)
        for widget in self._emails_frame.winfo_children():
            widget.destroy()

        def _load_emails(filter_type) -> [Email]:
            print("HI1")
            if filter_type == 'sent':
                self._current_filter_state[1] = True
            else:
                self._current_filter_state[1] = False

            for inner_widget in self._emails_frame.winfo_children():
                if inner_widget.winfo_class() == 'Label':
                    inner_widget.destroy()
            print("HI2")
            try:
                if filter_type == 'sent':
                    self._pop3_socket.send(b'sent')

                else:
                    self._pop3_socket.send(b'recv')
                print("HI3")
                len_to_receive = int.from_bytes(self._pop3_socket.recv(4), byteorder="big")
                print("HI4")
                print("len_to_receive:", len_to_receive)
                self._pop3_socket.send(b'ACK')
                print("HI5")
                data_received = self._pop3_socket.recv(int(len_to_receive))
                print("HI6")
                print(data_received, len(data_received))
                emails: [Email] = pickle.loads(data_received)
            except (socket.error, pickle.PickleError) as e:
                messagebox.showerror("Error occurred!", "Place - loading emails")
                print('-----------------------load emails error ------------------------', e)
                self._pop3_socket.close()
                self.start_pop3_connection()
                return

            print("HI7")
            print("THIS IS: ", emails)
            labels = [f"{Base64.Decrypt(email.sender)} -> {Base64.Decrypt(email.subject)} | {email.creation_date}"
                      for email in emails]

            for label_text, email in zip(labels, emails):
                label = tk.Label(self._emails_frame, text=label_text, bg="lightgray",
                                 relief="raised", cursor="hand2")
                label.bind("<Button-1>", lambda event, email2=email: self.open_single_email_window(email2))
                label.pack(fill=tk.X)
            self._emails_frame.pack(fill='both', expand=1)
            print("HI8")
            self._current_filter_state[0] = filter_type

        self._side_menu_frame = tk.Frame(self._emails_frame, bg="#f0f0f0")
        # Packing the side menu frame
        self._side_menu_frame.pack(side='right', fill='y', padx=10, pady=10)

        # Received button
        received_button = tk.Button(self._side_menu_frame, text="Received",
                                    command=lambda: _load_emails('recv'))
        received_button.pack(fill='x', pady=5)

        # Sent button
        sent_button = tk.Button(self._side_menu_frame, text="Sent",
                                command=lambda: _load_emails('sent'))
        sent_button.pack(fill='x', pady=5)

        # Send mail button (assuming you want it inside the mails frame)
        send_email_button = tk.Button(self._emails_frame, text="Send Email",
                                      command=self.open_send_email_window)
        send_email_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

        # Pack the main mails frame

        self._single_email_frame.pack_forget()
        self._send_email_frame.pack_forget()

        _load_emails(self._current_filter_state[0])

        # Implement or add placeholders for these methods

    def run(self):
        """
        Start the GUI event loop.
        """
        # Start the GUI event loop
        self.root.mainloop()

    def receive_emails(self):
        """
        Receive mails in a separate thread.
        """
        try:
            while self._run_receive_thread:
                print('current num:', threading.active_count())
                print("STARTING")
                code = self._transition_socket.recv(34)
                print("CODE1 IS: ", code)
                if code == b'-1':
                    break
                print('hey')
                self.root.after(0, lambda code1=code: self.update_gui_with_new_email(code1))
            print('bye')
        except socket.error as e:
            print('----------------Thread error-----------------', e)
            self._run_receive_thread = False

    def update_gui_with_new_email(self, email_id):
        """
        Update the GUI with a new mail.

        Parameters:
        - mail: The new mail object.
        """
        print("HELLO BROTHER")
        # TODO - problem with pressing received button
        # Update the GUI to reflect the new mail
        sleep(randint(1, 5) / 10)  # Avoid collisions
        print('EMAIL ID TO SEND TO GET:::', email_id)
        try:
            self._pop3_socket.send(b"==" + email_id)
            email_obj_len = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(b'ACK')
            email_dumps = self._pop3_socket.recv(email_obj_len)[4:]
            email_obj: Email = pickle.loads(email_dumps)
        except (socket.error, pickle.PickleError) as e:
            print('--------------------- error in update gui -------------------', e)
            self._pop3_socket.close()
            self.start_pop3_connection()
            self.update_gui_with_new_email(email_id)
            return

        print("STATE:", self._current_filter_state)
        if datetime.datetime.now() < email_obj.creation_date or self._current_filter_state[1] is True:
            return

        label = tk.Label(self._emails_frame,
                         text=f"{Base64.Decrypt(email_obj.sender)} -> {Base64.Decrypt(email_obj.subject)} | {email_obj.creation_date}",
                         bg="lightgray",
                         relief="raised",
                         cursor="hand2")

        label.bind("<Button-1>", lambda event, email2=email_obj: self.open_single_email_window(email2))
        label.pack(fill=tk.X)


# Example of how to use the User class
if __name__ == "__main__":
    user = User()
