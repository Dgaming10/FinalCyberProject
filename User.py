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
from random import choice
from math import ceil

import globals_module
from Base64 import Base64
from File import File
from Email import Email


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
    - open_login_page: Open the login page.
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
        self.root.geometry("550x600")
        self.root.configure(bg="#f0f0f0")
        self.root.protocol("WM_DELETE_WINDOW", self.close_program)

        self._login_frame = tk.Frame(self.root)
        self._register_frame = tk.Frame(self.root)
        self._emails_frame = tk.Frame(self.root)
        self._single_email_frame = tk.Frame(self.root)
        self._send_email_frame = tk.Frame(self.root)

        self._transition_socket: socket = None
        self._pop3_socket: socket = None
        self._is_scheduled_btn = tk.IntVar()
        self._receive_thread = None
        self._run_receive_thread = False
        self._running = True

        emails_top_label = tk.Label(self._emails_frame, text="MUN MAILS")
        emails_top_label.pack(side='top', pady=5)

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
        self._login_frame.pack(fill="both", expand=1)
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
        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%])[a-zA-Z\d!@#$%]{11,16}$"
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
        email_label = tk.Label(self._login_frame, text="Email", bg="#f0f0f0")
        email_label.pack(pady=10)

        email_login_entry = tk.Entry(self._login_frame, width=30, font=("Helvetica", 12),)
        email_login_entry.pack(pady=5)

        password_label = tk.Label(self._login_frame, text="Password:", bg="#f0f0f0")
        password_label.pack(pady=10)

        password_login_entry = tk.Entry(self._login_frame, show="•", width=30, font=("Helvetica", 12))
        password_login_entry.pack(pady=5)

        show_password_button = tk.Checkbutton(self._login_frame, text="Show Password",
                                              command=lambda: User.toggle_show_password(password_login_entry))
        show_password_button.pack()

        login_login_button = tk.Button(self._login_frame, text="Login",
                                       command=lambda: self.login(email_login_entry.get(), password_login_entry.get()),
                                       bg="#4caf50",
                                       fg="white", width=20, bd=0,
                                       font=("Helvetica", 12))

        login_login_button.pack(pady=10)

        login_register_button = tk.Button(self._login_frame, text="Don't have an account? Register!",
                                          command=self.open_register_page, bd=1)
        login_register_button.pack(pady=10)

    def login(self, email, password):
        """
        Handle the login process.

        Parameters:
        - email (str): The user's email.
        - password (str): The user's password.
        """
        # Add your login logic here
        if User.is_valid_email(email) and User.is_valid_password(password):
            self.stop_pop3_connection()
            self._email = Base64.Encrypt(email)
            self.start_pop3_connection()
            if self._running is False:
                return
            try:
                messagebox.showinfo("Login", f"Logged in with email: {email}")
                self._pop3_socket.send(b'LOGIN')
                self._pop3_socket.recv(3)

                random_prefix = ''.join(choice(globals_module.ASCII_LETTERS) for _ in range(4))
                login_tuple_pickle = random_prefix.encode() + pickle.dumps(
                    (Base64.Encrypt(email), Base64.Encrypt(password)))
                self._pop3_socket.send(len(login_tuple_pickle).to_bytes(4, byteorder='big'))
                self._pop3_socket.recv(3)
                self._pop3_socket.send(login_tuple_pickle)
                len_dict = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
                self._pop3_socket.send(b'ACK')
                user_dict = pickle.loads(self._pop3_socket.recv(len_dict)[4:])
                if len(user_dict.keys()) == 0:
                    messagebox.showerror("Login failed!", "Please try again")
                    self._pop3_socket.close()
                else:
                    messagebox.showinfo("Successful login!",
                                        f"Hey {Base64.Decrypt(user_dict['first_name'])}! Welcome to MailUN")

                    self._login_frame.destroy()
                    self._register_frame.destroy()
                    self._age = user_dict['age']
                    self._first_name = user_dict['first_name']
                    self._last_name = user_dict['last_name']
                    self._email = user_dict['email']
                    self.start_smtp_connection()
                    if self._running is False:
                        return
                    print("connected to server from", self._transition_socket)
                    print('calling restart_thread from login')
                    self.restart_thread()
                    self.root.title(
                        f"MailUN\tWelcome {Base64.Decrypt(self._first_name)} {Base64.Decrypt(self._last_name)}!")
            except (socket.error, pickle.PickleError) as e:
                print('------------------------- Login Error ---------------------------', e)
                messagebox.showerror("Error occurred!", "Logging in process")
                return
        else:
            messagebox.showerror("Error", "Invalid email or password format")

    def register(self, email, password, first_name, last_name, birth_date):
        """
        Handle the registration process.
        """
        try:
            # Parse the date string into a datetime object
            birth_date = datetime.datetime.strptime(birth_date, "%d-%m-%Y")

            # Check if the birthdate is not in the future
            if birth_date > datetime.datetime.now() or datetime.datetime.now().year - birth_date.year > 150:
                messagebox.showerror("Error occurred!", "Please enter a valid birth date")
                return

            if not self.is_valid_email(email):
                print('valid not', email, self.is_valid_email(email))
                messagebox.showerror("Error occurred!", "Invalid email format")
                return

            if not self.is_valid_password(password):
                messagebox.showerror("Error occurred!", "Invalid password format")
                return

            if not (2 < len(first_name) < 30 and 2 < len(
                    last_name) < 30 and first_name.isalpha() and last_name.isalpha()):
                messagebox.showerror("Error occurred!", "Invalid first name or last name format")
                return

            self.stop_pop3_connection()
            self._email = Base64.Encrypt(email)
            self.start_pop3_connection()
            self._pop3_socket.send(b'REGISTER')
            self._pop3_socket.recv(3)
            current_date = datetime.datetime.now()
            age = current_date.year - birth_date.year - ((current_date.month, current_date.day) <
                                                         (birth_date.month, birth_date.day))
            dict_so_send = {'email': Base64.Encrypt(email), 'password': Base64.Encrypt(password),
                            'first_name': Base64.Encrypt(first_name),
                            'last_name': Base64.Encrypt(last_name), 'age': age}
            pickle_dumps = pickle.dumps(dict_so_send)
            self._pop3_socket.send((len(pickle_dumps) + 4).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(3)
            random_prefix = ''.join(choice(globals_module.ASCII_LETTERS) for _ in range(4))
            self._pop3_socket.send(random_prefix.encode() + pickle_dumps[::-1])
            reg_code = self._pop3_socket.recv(1).decode()
            print('reg_Cide', reg_code)
            if reg_code == 'S':
                messagebox.showinfo("Successful register!",
                                    f"Hey {first_name}! Welcome to MailUN")
                self._login_frame.destroy()
                self._register_frame.destroy()
                self._age = age
                self._first_name = Base64.Encrypt(first_name)
                self._last_name = Base64.Encrypt(last_name)
                self.start_smtp_connection()
                if self._running is False:
                    return
                print("connected to server from", self._transition_socket)
                print('calling restart thread from register')
                self.restart_thread()
                self.root.title(
                    f"MailUN\tWelcome {Base64.Decrypt(self._first_name)} {Base64.Decrypt(self._last_name)}!")
            else:
                messagebox.showerror("Error occurred!", "Email address already exists or another error occurred")

        except ValueError:
            # If parsing fails, the date string is not valid
            messagebox.showerror("Error occurred!", "Please enter a valid birth date")
            return

    @staticmethod
    def toggle_show_password(password_entry_reg_register):
        if password_entry_reg_register.config()['show'][4] == '•':
            password_entry_reg_register.config(show="")
        else:
            password_entry_reg_register.config(show="•")

    def register_page(self):
        """
        Display the registration page.
        """
        registration_label_register = tk.Label(self._register_frame, text="Registration Form",
                                               font=("Helvetica", 16))
        registration_label_register.pack(pady=10)

        email_label_register = tk.Label(self._register_frame, text="Email (****@mun.com):")
        email_label_register.pack()

        email_entry_reg_register = tk.Entry(self._register_frame, width=30)
        email_entry_reg_register.pack()

        password_label_register = tk.Label(self._register_frame, text="Password:")
        password_label_register.pack()

        password_entry_reg_register = tk.Entry(self._register_frame, show="•", width=30)
        password_entry_reg_register.pack()

        show_password_button = tk.Checkbutton(self._register_frame, text="Show Password",
                                              command=lambda: User.toggle_show_password(password_entry_reg_register))
        show_password_button.pack()

        first_name_label_register = tk.Label(self._register_frame, text="First Name:")
        first_name_label_register.pack()

        first_name_entry_register = tk.Entry(self._register_frame, width=30)
        first_name_entry_register.pack()

        last_name_label_register = tk.Label(self._register_frame, text="Last Name:")
        last_name_label_register.pack()

        last_name_entry_register = tk.Entry(self._register_frame, width=30)
        last_name_entry_register.pack()

        birth_date_label_register = tk.Label(self._register_frame, text="Birth Date (DD-MM-YYYY):")
        birth_date_label_register.pack()

        birth_date_entry_register = tk.Entry(self._register_frame, width=30)
        birth_date_entry_register.pack()

        register_button_register = tk.Button(self._register_frame, text="Submit",
                                             command=lambda: self.register(email_entry_reg_register.get(),
                                                                           password_entry_reg_register.get(),
                                                                           first_name_entry_register.get(),
                                                                           last_name_entry_register.get(),
                                                                           birth_date_entry_register.get()),
                                             bg="#4caf50", fg="white",
                                             width=25, bd=0,
                                             font=("Helvetica", 12))
        register_button_register.pack(pady=10)

        login_button1 = tk.Button(self._register_frame, text="Login", command=self.open_login_page, bg="#2196F3",
                                  fg="white",
                                  width=25,
                                  font=("Helvetica", 13), bd=0)

        login_button1.pack(pady=10)

        hello_label_register = tk.Label(self._register_frame, text="Your password must:\n"
                                                                   "- Contain at least 1 lowercase letter (a-z)\n"
                                                                   "- Contain at least 1 uppercase letter (A-Z)\n"
                                                                   "- Contain at least 1 digit (0-9)\n"
                                                                   "- Contain at least 1 symbol out of !@#$%\n"
                                                                   "- Be between 11 and 16 characters in length\n"
                                                                   "\n"
                                                                   "Allowed characters: Lowercase letters (a-z), "
                                                                   "Uppercase letters (A-Z), Digits (0-9), "
                                                                   "Symbols (!@#$%)"
                                        )
        hello_label_register.pack(pady=10)

    def open_login_page(self):
        """
        Open the login page.
        """
        self._login_frame.pack(fill='both', expand=1)
        self._register_frame.forget()

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
        send_email_recipients_label = tk.Label(self._send_email_frame, text="Recipients:")
        send_email_recipients_label.pack()

        send_email_recipients_entry = tk.Entry(self._send_email_frame)
        send_email_recipients_entry.pack(fill="x")

        # Subject
        send_email_subject_label = tk.Label(self._send_email_frame, text="Subject:")
        send_email_subject_label.pack()

        send_email_subject_entry = tk.Entry(self._send_email_frame)
        send_email_subject_entry.pack(fill="x")

        # Message
        send_email_message_label = tk.Label(self._send_email_frame, text="Message:")
        send_email_message_label.pack()

        send_email_message_text = tk.Text(self._send_email_frame, height=10, width=40)
        send_email_message_text.pack()

        send_email_scheduled_label = tk.Label(self._send_email_frame, text="Message:")
        send_email_scheduled_label.pack()

        send_email_scheduled_date = DateEntry(self._send_email_frame, width=12, background='darkblue',
                                              foreground='white', borderwidth=2, mindate=datetime.date.today())
        send_email_scheduled_date.pack(pady=10)

        send_email_scheduled_hour = ttk.Spinbox(
            self._send_email_frame,
            from_=0,
            to=23,
            wrap=True,
            width=3
        )
        send_email_scheduled_hour.set("0")
        send_email_scheduled_hour.place(relx=0.6, rely=0.8, anchor=tk.CENTER)

        send_email_scheduled_hour_label = tk.Label(self._send_email_frame, text="Hours:")
        send_email_scheduled_hour_label.place(relx=0.6, rely=0.75, anchor=tk.CENTER)

        send_email_scheduled_minute = ttk.Spinbox(
            self._send_email_frame,
            from_=0,
            to=59,
            wrap=True,
            width=3
        )
        send_email_scheduled_minute.set("0")
        send_email_scheduled_minute.place(relx=0.7, rely=0.8, anchor=tk.CENTER)

        send_email_scheduled_minute_label = tk.Label(self._send_email_frame, text="Minutes:")
        send_email_scheduled_minute_label.place(relx=0.7, rely=0.75, anchor=tk.CENTER)

        send_email_scheduled_check_btn = tk.Checkbutton(
            self._send_email_frame, text='Enable Scheduled Email', variable=self._is_scheduled_btn,
            onvalue=True, offvalue=False)
        send_email_scheduled_check_btn.place(relx=0.3, rely=0.8, anchor=tk.CENTER)

        send_email_send_button = tk.Button(self._send_email_frame, text="Send", bg="#4caf50",
                                           command=lambda: self.send_email(send_email_recipients_entry.get()
                                                                           , send_email_scheduled_date.get_date(),
                                                                           send_email_subject_entry.get(),
                                                                           send_email_message_text.get("1.0", 'end-1c'),
                                                                           send_email_send_button,
                                                                           send_email_scheduled_hour.get(),
                                                                           send_email_scheduled_minute.get()))
        send_email_send_button.pack()

        send_email_open_file_button = tk.Button(self._send_email_frame, text="Choose files",
                                                command=self.select_files, bg="#FFFF33")
        send_email_open_file_button.place(relx=0.5, rely=0.65, anchor=tk.CENTER)
        send_email_back_button = tk.Button(self._send_email_frame, text="Go Back",
                                           command=self.restart_thread)
        send_email_back_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

        self._send_email_frame.pack(fill='both', expand=1)

    def validate_before_send(self, hours, minutes, recipients, scheduled_date):
        """
        Validate input before sending an email.

        Returns:
        bool: True if the input is valid, False otherwise.
        """
        if recipients == '':
            messagebox.showerror("Error", "Please enter a one or more recipient")
            return False
        elif self._is_scheduled_btn.get() == 1:
            try:
                current_time = datetime.datetime.now()
                if (scheduled_date == datetime.date.today() and
                        datetime.datetime(current_time.year, current_time.month, current_time.day,
                                          int(hours), int(minutes)) < current_time):
                    raise ValueError

            except ValueError:
                messagebox.showerror("Error", "Please enter a valid time and date")
                return False

        return True

    def restart_thread(self):
        try:
            if not (self._transition_socket is None or (self._receive_thread is not None and
                                                        self._receive_thread.is_alive() is True)):
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
            self._pop3_socket.connect((globals_module.POP3_SERVER_IP, globals_module.POP3_SERVER_PORT))
            self._pop3_socket.send(self._email.encode())
            self._pop3_socket.recv(3)
        except socket.error:
            messagebox.showerror("Error occurred!", "Place - connecting to the pop3 server")
            try:
                self._pop3_socket.close()
            finally:
                self.close_program()

    def stop_pop3_connection(self):
        if self._pop3_socket is None:
            return
        try:
            self._pop3_socket.close()
        except socket.error:
            messagebox.showerror("Error occurred!", "Place - disconnecting from the pop3 server")

    def start_smtp_connection(self):
        try:
            self._transition_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._transition_socket.connect((globals_module.SMTP_SERVER_IP, globals_module.SMTP_SERVER_PORT))
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
                self._running = False

    def send_email(self, recipients, send_email_scheduled_date, subject, message, send_email_send_button,
                   hours, minutes):
        """
        Send an email.
        """
        validation_ans = self.validate_before_send(hours, minutes, recipients, send_email_scheduled_date)

        if validation_ans is False:
            return

        print('is alive?', self._receive_thread.is_alive(), threading.active_count())
        emails: str = recipients
        realEmails = [Base64.Encrypt(i.strip()) for i in emails.split(',') if i != ""]

        realEmails = list(set(realEmails))
        print(f"mail sent from {self._email} to: {realEmails}")

        if self._is_scheduled_btn.get() == 1:
            new_datetime = datetime.datetime(year=send_email_scheduled_date.year,
                                             month=send_email_scheduled_date.month,
                                             day=send_email_scheduled_date.day,
                                             hour=int(hours),
                                             minute=int(minutes))
            sendEmail: Email = Email(self._email, realEmails,
                                     Base64.Encrypt(subject),
                                     Base64.Encrypt(message),
                                     new_datetime)
        else:
            sendEmail: Email = Email(self._email, realEmails,
                                     Base64.Encrypt(subject),
                                     Base64.Encrypt(message))

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
            print('calling restart thread from send_email')
            self.restart_thread()
            return

        print("EMAIL SENT! ", sentBytes)

        send_email_send_button.configure(state='disabled')
        self._send_email_frame.after(2000, lambda: send_email_send_button.configure(state='normal'))

    def open_register_page(self):
        """
        Open the registration page.
        """
        self._register_frame.pack(fill='both', expand=1)
        self._login_frame.forget()

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
            self._pop3_socket.send(b'FILE_CON')
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
        print('enterig delete_email')
        self._pop3_socket.send(b'DELETE')
        self._pop3_socket.recv(3)
        email_tup_dumps = pickle.dumps((email_obj.mongo_id, self._email))[::-1]
        self._pop3_socket.send(len(email_tup_dumps).to_bytes(4, byteorder='big'))
        self._pop3_socket.recv(3)
        self._pop3_socket.send(email_tup_dumps)
        self._pop3_socket.recv(3)
        messagebox.showinfo("Email got deleted!")
        self.open_emails_window()

    def open_single_email_window(self, email):
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
            if self._running is False:
                return
            self.open_emails_window(None)
            return

        single_email_frame_label = tk.Label(self._single_email_frame, text=Base64.Decrypt(email.message),
                                            bg="lightgray",
                                            relief="raised")

        single_email_frame_label.pack(fill=tk.X)
        single_email_frame_label.bind("<Button-1>", self.open_emails_window)

        elements_list = [f'{tup[1]}.{tup[2]}' for tup in files_received_obj]

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
        emails_label_text = ""
        if self._current_filter_state[0] == 'recv':
            emails_label_text = 'received from: ' + Base64.Decrypt(email.sender)
        else:
            emails_label_text = 'sent to: ' + ','.join([Base64.Decrypt(sent_email) for sent_email in email.recipients])
        emails_label = tk.Label(self._single_email_frame, text=emails_label_text)
        # Pack the label at the bottom center
        emails_label.pack(side=tk.BOTTOM, pady=10)
        single_email_save_button = tk.Button(self._single_email_frame, text="Save email",
                                             command=lambda: User.saveEmail(email))
        single_email_save_button.pack(side=tk.BOTTOM, pady=5)

        single_email_delete_button = tk.Button(self._single_email_frame, text="Delete email",
                                               command=lambda: self.delete_email(email))
        single_email_delete_button.pack(side=tk.BOTTOM, pady=5)

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

            if filter_type == 'sent':
                self._current_filter_state[1] = True
            else:
                self._current_filter_state[1] = False

            for inner_widget in self._emails_frame.winfo_children():
                if inner_widget.winfo_class() == 'Label':
                    inner_widget.destroy()

            try:
                if filter_type == 'sent':
                    self._pop3_socket.send(b'SENT')

                else:
                    self._pop3_socket.send(b'RECV')

                len_to_receive = int.from_bytes(self._pop3_socket.recv(4), byteorder="big")

                print("len_to_receive:", len_to_receive)
                self._pop3_socket.send(b'ACK')

                data_received = self._pop3_socket.recv(int(len_to_receive))

                emails: [Email] = pickle.loads(data_received[4:])
            except (socket.error, pickle.PickleError) as e:
                messagebox.showerror("Error occurred!", "Place - loading emails")
                print('-----------------------load emails error ------------------------', e)
                self._pop3_socket.close()
                self.start_pop3_connection()
                return

            labels = [f"{Base64.Decrypt(email.sender)} -> {Base64.Decrypt(email.subject)} | {email.creation_date}"
                      for email in emails]

            for label_text, email in zip(labels, emails):
                label = tk.Label(self._emails_frame, text=label_text, bg="lightgray",
                                 relief="raised", cursor="hand2", fg="#333", bd = 1)
                label.bind("<Button-1>", lambda event, email2=email: self.open_single_email_window(email2))
                label.pack(fill=tk.X)
            self._emails_frame.pack(fill='both', expand=1)
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
            print("STARTING")
            while self._run_receive_thread:
                print('current num:', threading.active_count())
                code = self._transition_socket.recv(ceil((globals_module.OBJECT_ID_LENGTH * 4) / 3) + 2)
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
