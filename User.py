import datetime
import pickle
import re
import socket
import threading
from time import sleep
import tkinter as tk
from os import path
from tkinter import messagebox, ttk, filedialog

from tkcalendar import DateEntry

import globals_module
from CryptoService import CryptoService
from Email import Email
from File import File


class User:
    """
    Class representing a user in the MailUN application.

    Attributes:
    - files_list (list): List of files the user wants to send
    - age (int): The age of the user.
    - first_name (str): The first name of the user.
    - last_name (str): The last name of the user.
    - email (str): The email address of the user.
    - root (tk.Tk): The main Tkinter window.
    - login_frame (tk.Frame): The login page frame.
    - register_frame (tk.Frame): The registration page frame.
    - emails_frame (tk.Frame): The frame for displaying mails.
    - single_email_frame (tk.Frame): The frame for displaying a single mail.
    - send_email_frame (tk.Frame): The frame for sending emails.
    - registration_label_register (tk.Label): Label for registration form.
    - transition_socket (socket.socket): The SMTP socket used for sending emails
    - pop3_server (socket.socket): The pop3 socket used for viewing emails and logging in operations
    - is_scheduled_btn (tk.IntVar): Indicator for scheduling the sent email
    - receive_thread (threading.Thread): The thread for receiving emails
    - run_receive_thread (bool): Flag for running the thread
    - running (bool): Flag for running the program
    - side_menu_frame (tk.Frame): The frame for the side menu in the emails window
    - current_filter_state (list): The current state of the emails viewed
    """

    def __init__(self):
        """
        Initialize the User instance.
        """
        self._smtp_key = None
        self._def_enc_len = None
        self._ack_enc = None
        self._files_list = []
        self._first_name = None
        self._last_name = None
        self._email = None
        self._pop3_key = None

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

        self._smtp_socket: socket = None
        self._pop3_socket: socket = None
        self._is_scheduled_btn = tk.IntVar()
        self._receive_thread = None
        self._run_receive_thread = False
        self._running = True

        self._side_menu_frame = tk.Frame(self._emails_frame, bg="#f0f0f0")

        self._current_filter_state = ["recv", False]

        self.initialize_gui()

    def initialize_gui(self):
        """
        Initialize the GUI elements.
        """

        self.init_login_page()
        self.init_register_page()
        self.init_send_email_window()
        # Initialize pages
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
        username_pattern = r"^[a-zA-Z0-9\-_\.]{5,32}$"
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

    def init_login_page(self):
        """
        Initializes the login page.
        """
        email_label = tk.Label(self._login_frame, text="Email", bg="#f0f0f0")
        email_label.pack(pady=10)

        email_login_entry = tk.Entry(self._login_frame, width=30, font=("Helvetica", 12), )
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

        if User.is_valid_email(email) and User.is_valid_password(password):
            self.stop_pop3_connection()
            self.start_pop3_connection(email)
            # TODO -> change start pop3 and smtp and all decrypt / encrypt
            # TODO -> delete all prints and irrelevant comments
            # TODO -> add """ where needed in the other files
            # TODO -> design a bit
            if self._running is False:
                return
            try:
                messagebox.showinfo("Login", f"Logged in with email: {email}")
                enc_cmd = CryptoService.encrypt_string('LOGIN', self._pop3_key)
                self._pop3_socket.send(len(enc_cmd).to_bytes(4, byteorder='big'))
                self._pop3_socket.recv(self._def_enc_len)
                self._pop3_socket.send(enc_cmd)
                self._pop3_socket.recv(self._def_enc_len)

                login_tuple_pickle = CryptoService.encrypt_obj(pickle.dumps((email, password)), self._pop3_key)
                self._pop3_socket.send(len(login_tuple_pickle).to_bytes(4, byteorder='big'))
                self._pop3_socket.recv(self._def_enc_len)
                self._pop3_socket.send(login_tuple_pickle)
                len_dict = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
                self._pop3_socket.send(self._ack_enc)
                user_dict = pickle.loads(CryptoService.decrypt_obj(self._pop3_socket.recv(len_dict), self._pop3_key))
                self._pop3_socket.send(self._ack_enc)
                if len(user_dict.keys()) == 0:
                    messagebox.showerror("Login failed!", "Please try again")
                    self.stop_pop3_connection()
                else:
                    messagebox.showinfo("Successful login!",
                                        f"Hey {CryptoService.decrypt_string(user_dict['first_name'])}!"
                                        f" Welcome to MailUN")
                    print(email)
                    self._login_frame.destroy()
                    self._register_frame.destroy()
                    self._first_name = user_dict['first_name']
                    self._last_name = user_dict['last_name']
                    self._email = CryptoService.encrypt_string(email)
                    self.start_smtp_connection()
                    if self._running is False:
                        return
                    print("connected to server from", self._smtp_socket)
                    self.restart_thread()
                    self.root.title(
                        f"MailUN\tWelcome {CryptoService.decrypt_string(self._first_name)}"
                        f" {CryptoService.decrypt_string(self._last_name)}!")

            except (socket.error, pickle.PickleError) as e:
                print('------------------------- Login Error ---------------------------', e)
                messagebox.showerror("Error occurred!", "Logging in process")
                return
        else:
            messagebox.showerror("Error", "Invalid email or password format")

    def register(self, email, password, first_name, last_name, birth_date):
        """
        Handle the registration process.

        Parameters:
        - email (str): The user's email.
        - password (str): The user's password.
        - first_name (str): The user's first name
        - last_name (str): The user's last name
        - birth_date (datetime.datetime): The user's birthdate
        """
        try:

            birth_date = datetime.datetime.strptime(birth_date, "%d-%m-%Y")

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
            self._email = CryptoService.encrypt_string(email)
            self.start_pop3_connection(email)
            enc_cmd = CryptoService.encrypt_string('REGISTER', self._pop3_key)
            self._pop3_socket.send(len(enc_cmd).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(self._def_enc_len)
            self._pop3_socket.send(enc_cmd)
            self._pop3_socket.recv(self._def_enc_len)
            dict_so_send = {'email': email,
                            'password': CryptoService.hash_string(password),
                            'first_name': CryptoService.encrypt_string(first_name),
                            'last_name': CryptoService.encrypt_string(last_name), 'birth_date': str(birth_date.date())}
            dict_so_send = CryptoService.encrypt_obj(pickle.dumps(dict_so_send), self._pop3_key)
            self._pop3_socket.send(len(dict_so_send).to_bytes(4, 'big'))
            self._pop3_socket.recv(self._def_enc_len)
            self._pop3_socket.send(dict_so_send)
            reg_code = CryptoService.decrypt_string(self._pop3_socket.recv(self._def_enc_len).decode(), self._pop3_key)
            self._pop3_socket.send(self._ack_enc)
            if reg_code == 'S':
                messagebox.showinfo("Successful register!",
                                    f"Hey {first_name}! Welcome to MailUN")
                self._login_frame.destroy()
                self._register_frame.destroy()
                self._first_name = CryptoService.encrypt_string(first_name)
                self._last_name = CryptoService.encrypt_string(last_name)
                self.start_smtp_connection()
                if self._running is False:
                    return
                self.restart_thread()
                self.root.title(
                    f"MailUN\tWelcome {first_name} {last_name}!")
            else:
                self._email = ""
                messagebox.showerror("Error occurred!", "Email address already exists or another error occurred")

        except ValueError:
            messagebox.showerror("Error occurred!", "Please enter a valid birth date")
            return

    @staticmethod
    def toggle_show_password(password_entry_reg_register):
        """
        Toggles the show password button

        Parameters:
        - password_entry_reg_register (tk.Entry): Password entry in the register form
        """
        if password_entry_reg_register.config()['show'][4] == '•':
            password_entry_reg_register.config(show="")
        else:
            password_entry_reg_register.config(show="•")

    def init_register_page(self):
        """
        Initializes the registration page.
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
        Opens the login page.
        """
        self._login_frame.pack(fill='both', expand=1)
        self._register_frame.forget()

    def select_files(self):
        """
        Opens and selects the wished files
        """
        filename = tk.filedialog.askopenfilenames(title="Select files",
                                                  filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        self._files_list = filename

    def init_send_email_window(self):
        """
        Initializes the send email page
        """
        send_email_recipients_label = tk.Label(self._send_email_frame, text="Recipients:")
        send_email_recipients_label.pack()

        send_email_recipients_entry = tk.Entry(self._send_email_frame)
        send_email_recipients_entry.pack(fill="x")

        send_email_subject_label = tk.Label(self._send_email_frame, text="Subject:")
        send_email_subject_label.pack()

        send_email_subject_entry = tk.Entry(self._send_email_frame)
        send_email_subject_entry.pack(fill="x")

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

    def open_send_email_window(self):
        """
        Opens the window for sending emails.
        """
        self._current_filter_state[1] = True
        self._emails_frame.pack_forget()

        self._send_email_frame.pack(fill='both', expand=1)
        # TODO -> add open_send_email_window and init_send_email_window

    def validate_before_send(self, hours, minutes, recipients, scheduled_date):
        """
        Validate input before sending an email.

        Parameters:
        - hours (int): The wished hour of the scheduled email
        - minutes (int): The wished minute of the scheduled email
        - recipients (list): The recipients list
        - scheduled_date (datime.date): The date of the scheduled email

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
                    # If the selected time is in the past (past dates cannot be chosen) raise an error
                    raise ValueError

            except ValueError:
                messagebox.showerror("Error", "Please enter a valid time and date")
                return False

        return True

    def restart_thread(self):
        """
        Restarts the receiving thread
        """
        try:
            if not (self._smtp_socket is None or (self._receive_thread is not None and
                                                  self._receive_thread.is_alive() is True)):
                # Check if the thread can indeed be restarted
                print('SMTP KEY:', self._smtp_key)
                print('SMTP ENC:', CryptoService.encrypt_string('OPEN', self._smtp_key))
                self._smtp_socket.send(CryptoService.encrypt_string('OPEN', self._smtp_key))
                self._receive_thread = threading.Thread(target=self.receive_emails)
                # Threads cannot be restarted, so it needs to be initialized again
                self._run_receive_thread = True
                self._receive_thread.start()
            self.open_emails_window()
        except (threading.ThreadError, socket.error):
            print('-------------------- error in restarting thread -------------------------')
            messagebox.showerror("Error occurred!", "Place - restarting thread")

    def start_pop3_connection(self, email):
        """
        Starts the pop3 socket
        """
        try:
            self._pop3_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._pop3_socket.connect((globals_module.POP3_SERVER_IP, globals_module.POP3_SERVER_PORT))
            key_len = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(b'ACK')
            self._pop3_key = self._pop3_socket.recv(key_len)[::-1]
            enc_email = CryptoService.encrypt_string(email, self._pop3_key)
            self._ack_enc = CryptoService.encrypt_string("ACK", self._pop3_key)
            self._def_enc_len = len(self._ack_enc)
            # To make it easier to access, the encryption of 'ACK' and its length are saved as class attributes
            self._pop3_socket.send(len(enc_email).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(self._def_enc_len)
            self._pop3_socket.send(enc_email)
            self._pop3_socket.recv(self._def_enc_len)
        except socket.error:
            messagebox.showerror("Error occurred!", "Place - connecting to the pop3 server")
            try:
                self._pop3_socket.close()
            finally:
                self.close_program()

    def stop_pop3_connection(self):
        """
        Stops the pop3 socket
        """
        if self._pop3_socket is None:
            return
        try:
            self._pop3_socket.close()
        except socket.error:
            messagebox.showerror("Error occurred!", "Place - disconnecting from the pop3 server")

    def start_smtp_connection(self):
        """
        Starts the transition (smtp) socket
        """
        try:
            self._smtp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._smtp_socket.connect((globals_module.SMTP_SERVER_IP, globals_module.SMTP_SERVER_PORT))
            key_len = int.from_bytes(self._smtp_socket.recv(4), byteorder='big')
            self._smtp_socket.send(b'ACK')
            self._smtp_key = self._smtp_socket.recv(key_len)[::-1]
            enc_email = CryptoService.encrypt_string(CryptoService.decrypt_string(self._email),
                                                     self._smtp_key)

            self._smtp_socket.send(len(enc_email).to_bytes(4, byteorder='big'))
            self._smtp_socket.recv(self._def_enc_len)
            self._smtp_socket.send(enc_email)
            self._smtp_socket.recv(self._def_enc_len)
        except socket.error:
            messagebox.showerror("Error occurred!", "Place - connecting to the smtp server")
            try:
                self._smtp_socket.close()
            finally:
                self.close_program()

    def close_program(self):
        """
        Closes the program (User GUI & connections & thread)
        """
        self._run_receive_thread = False
        try:
            if self._pop3_socket is not None:
                self._pop3_socket.close()
        finally:
            try:
                if self._smtp_socket is not None:
                    self._smtp_socket.close()
            finally:
                # By this time, the receiving thread might cause an error and will close itself
                self._pop3_socket = None
                self._smtp_socket = None
                self.root.destroy()
                self._running = False

    def send_email(self, recipients, send_email_scheduled_date, subject, message, send_email_send_button,
                   hours, minutes):
        """
        Sends an email.

        Parameters:
        - recipients (list): The recipients of the current email
        - send_email_scheduled_date (datetime.date): The scheduled date (if there is one)
        - subject (str): The subject of the current email
        - message (str): The message of the current email
        - send_email_send_button (tk.Button): The button that sends the email
        - hours (int): The hours of the scheduled time
        - minutes (int): The minute of the scheduled time
        """

        validation_ans = self.validate_before_send(hours, minutes, recipients, send_email_scheduled_date)

        if validation_ans is False:
            return

        emails: str = recipients
        real_emails = [CryptoService.encrypt_b64(i.strip())[::-1] for i in emails.split(',') if i != ""]

        real_emails = list(set(real_emails))
        # Remove duplicates, if there are

        if self._is_scheduled_btn.get() == 1:
            new_datetime = datetime.datetime(year=send_email_scheduled_date.year,
                                             month=send_email_scheduled_date.month,
                                             day=send_email_scheduled_date.day,
                                             hour=int(hours),
                                             minute=int(minutes))
            send_email: Email = Email(CryptoService.decrypt_string(self._email), real_emails,
                                      subject,
                                      message,
                                      new_datetime)
        else:
            send_email: Email = Email(CryptoService.decrypt_string(self._email), real_emails,
                                      subject,
                                      message)

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

            file_object_list.append(File(CryptoService.encrypt_string(file_path_name),
                                         CryptoService.encrypt_string(file_path_ex), current_file_content))

        try:

            if self._receive_thread.is_alive() is True:
                self._smtp_socket.send(CryptoService.encrypt_string('CLSE', self._smtp_key))
                # Close the thread in order to avoid a race condition, it won't need to receive any emails here anyway
                self._run_receive_thread = False
                self._receive_thread.join()

            if self._is_scheduled_btn.get() != 1:
                # Might be a delay between the click until the actual operation
                send_email.update_creation_date()

            send_email_dumps = CryptoService.encrypt_obj(pickle.dumps(send_email), self._smtp_key)

            files_list_dumps = CryptoService.encrypt_obj(pickle.dumps(file_object_list), self._smtp_key)
            self._smtp_socket.send(CryptoService.encrypt_string('SEND', self._smtp_key))
            self._smtp_socket.recv(self._def_enc_len)
            self._smtp_socket.send(len(files_list_dumps).to_bytes(4, byteorder='big'))
            self._smtp_socket.recv(self._def_enc_len)
            self._smtp_socket.send(files_list_dumps)
            self._smtp_socket.recv(self._def_enc_len)
            self._smtp_socket.send(len(send_email_dumps).to_bytes(4, byteorder='big'))
            self._smtp_socket.recv(self._def_enc_len)

            self._smtp_socket.send(send_email_dumps)

            self._smtp_socket.recv(self._def_enc_len)

        except (socket.error, pickle.PickleError) as e:
            print('----------------------- error in sending email --------------------', e)
            messagebox.showerror("Error occurred!", "Place - sending email")
            self._smtp_socket.close()
            if self._receive_thread.is_alive() is True:
                self._run_receive_thread = False
                self._receive_thread.join()

            self.start_smtp_connection()
            self.restart_thread()
            return

        send_email_send_button.configure(state='disabled')
        self._send_email_frame.after(2000, lambda: send_email_send_button.configure(state='normal'))
        # Disable sending alot of requests in a short time (spamming)

    def open_register_page(self):
        """
        Opens the registration page.
        """

        self._register_frame.pack(fill='both', expand=1)
        self._login_frame.forget()

    @staticmethod
    def save_email(email_obj):
        """
        Saves an email's "summery" to the user's PC

        Parameters:
        - email_obj (Email): The object of the email the user want to save
        """
        file_to_save = tk.filedialog.asksaveasfile(defaultextension='.txt', filetypes=[("Text file", ".txt")])

        if not file_to_save:
            return

        files_names = "None"
        print('FILES INFO', email_obj.files_info)
        if email_obj.files_info:
            files_names = ", ".join(f'{tup[0]}.{tup[1]}' for tup in email_obj.files_info)
        file_content = (
            f'Date:{email_obj.creation_date}\nFrom:{email_obj.sender}\n'
            f'To:{email_obj.recipients}\n'
            f'Subject:{email_obj.subject[::-1]}\n'
            f'Message:{email_obj.message[::-1]}\n'
            f'Files:{files_names}')

        file_to_save.write(file_content)
        file_to_save.close()

    def save_file(self, file_info, recipients):
        """
        Saves the current file to the user's PC

        Parameters:
        - file_info (list): The info of the saved file

        """
        print('file_info:', file_info)
        file_path = filedialog.asksaveasfilename(initialfile=f'{file_info[1]}.{file_info[2]}',
                                                 defaultextension=f'.{file_info[2]}',
                                                 filetypes=[("All files", "*.*")])
        if file_path:
            enc_cmd = CryptoService.encrypt_string('FILE_CON', self._pop3_key)
            self._pop3_socket.send(len(enc_cmd).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(self._def_enc_len)
            self._pop3_socket.send(enc_cmd)
            self._pop3_socket.recv(self._def_enc_len)
            enc_id = CryptoService.encrypt_string(str(file_info[0]), self._pop3_key)
            self._pop3_socket.send(len(enc_id).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(self._def_enc_len)
            self._pop3_socket.send(enc_id)
            file_content_length = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(self._ack_enc)
            recipients = [CryptoService.encrypt_b64(i.strip())[::-1] for i in recipients]
            shared_key = CryptoService.generate_files_key(recipients)
            print(recipients)
            print("SK:", shared_key)

            file_content = self._pop3_socket.recv(file_content_length)
            print("CON:",file_content )
            file_content = CryptoService.decrypt_obj(file_content, shared_key)
            self._pop3_socket.send(self._ack_enc)
            selected_file = open(file_path, 'wb')
            selected_file.write(file_content)
            selected_file.close()

    def delete_email(self, email_obj):
        """
        Deletes an email

        Parameters:
        - email_obj (Email): The object of the email

        """
        enc_cmd = CryptoService.encrypt_string('DELETE', self._pop3_key)
        self._pop3_socket.send(len(enc_cmd).to_bytes(4, byteorder='big'))
        self._pop3_socket.recv(self._def_enc_len)
        self._pop3_socket.send(enc_cmd)
        self._pop3_socket.recv(self._def_enc_len)
        email_tup_dumps = CryptoService.encrypt_obj(pickle.dumps((email_obj.mongo_id, self._email)), self._pop3_key)
        self._pop3_socket.send(len(email_tup_dumps).to_bytes(4, byteorder='big'))
        self._pop3_socket.recv(self._def_enc_len)
        self._pop3_socket.send(email_tup_dumps)
        self._pop3_socket.recv(self._def_enc_len)
        messagebox.showinfo("Email got deleted!")
        self.open_emails_window()

    def open_single_email_window(self, email: Email):
        """
        Opens the window of a specific mail.

        Parameters:
        - email (Email): The info of the email
        """

        self._current_filter_state[1] = True
        for widget in self._single_email_frame.winfo_children():
            widget.destroy()

        try:
            enc_cmd = CryptoService.encrypt_string(str(email.mongo_id), self._pop3_key)
            self._pop3_socket.send(len(enc_cmd).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(self._def_enc_len)
            self._pop3_socket.send(enc_cmd)
            self._pop3_socket.recv(self._def_enc_len)
            files_received_obj_length = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(self._ack_enc)
            files_received_obj = pickle.loads(
                CryptoService.decrypt_obj(self._pop3_socket.recv(files_received_obj_length), self._pop3_key))
            self._pop3_socket.send(self._ack_enc)
        except (socket.error, pickle.PickleError) as e:
            print('-------------------- single email error -----------------------', e)
            messagebox.showerror("Error occurred!", "Place - getting single email")
            self._pop3_socket.close()
            self.start_pop3_connection(CryptoService.decrypt_string(self._email))
            if self._running is False:
                return
            self.open_emails_window()
            return

        single_email_frame_label = tk.Label(self._single_email_frame,
                                            text=CryptoService.decrypt_string(email.message),
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

        for i, element in enumerate(elements_list):
            button = tk.Button(grid_frame, text=element,
                               command=lambda index=i: self.save_file(files_received_obj[index], email.recipients))
            row, col = divmod(i, cols)
            button.grid(row=row, column=col, padx=5, pady=5)
            email.files_info.append((files_received_obj[i][1], files_received_obj[i][2]))

        if self._current_filter_state[0] == 'recv':
            emails_label_text = 'received from: ' + email.sender
        else:
            emails_label_text = 'sent to: ' + ','.join(email.recipients)
        emails_label = tk.Label(self._single_email_frame, text=emails_label_text)

        emails_label.pack(side=tk.BOTTOM, pady=10)
        single_email_save_button = tk.Button(self._single_email_frame, text="Save email",
                                             command=lambda: User.save_email(email))
        single_email_save_button.pack(side=tk.BOTTOM, pady=5)

        single_email_delete_button = tk.Button(self._single_email_frame, text="Delete email",
                                               command=lambda: self.delete_email(email))
        single_email_delete_button.pack(side=tk.BOTTOM, pady=5)

        self._emails_frame.pack_forget()
        self._single_email_frame.pack(fill='both', expand=1)

    def open_emails_window(self, e=None):
        """
        Opens the window for displaying mails.

        Parameters:
        - e: An optional event parameter.
        """

        for widget in self._emails_frame.winfo_children():
            widget.destroy()
            # Clear the window in order to update it with the new emails from the DB

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
                    enc_cmd = CryptoService.encrypt_string('SENT', self._pop3_key)

                else:
                    enc_cmd = CryptoService.encrypt_string('RECV', self._pop3_key)

                self._pop3_socket.send(len(enc_cmd).to_bytes(4, byteorder='big'))
                self._pop3_socket.recv(self._def_enc_len)
                print('1', len(enc_cmd))
                self._pop3_socket.send(enc_cmd)
                self._pop3_socket.recv(self._def_enc_len)
                print('2')
                len_to_receive = int.from_bytes(self._pop3_socket.recv(4), byteorder="big")
                print('3', len_to_receive)
                self._pop3_socket.send(self._ack_enc)

                emails_received = self._pop3_socket.recv(len_to_receive)
                print('4', emails_received)
                emails: [Email] = pickle.loads(CryptoService.decrypt_obj(emails_received, self._pop3_key))
                self._pop3_socket.send(self._ack_enc)
            except (socket.error, pickle.PickleError) as ex:
                messagebox.showerror("Error occurred!", "Place - loading emails")
                print('-----------------------load emails error ------------------------', ex)
                self._pop3_socket.close()
                sleep(2)
                self.start_pop3_connection(CryptoService.decrypt_string(self._email))
                self.open_emails_window()
                return

            labels = [
                (f"{email.sender} -> {CryptoService.decrypt_string(email.subject)}"
                 f" | {email.creation_date}")
                for email in emails]

            for label_text, email in zip(labels, emails):
                label = tk.Label(self._emails_frame, text=label_text, bg="lightgray",
                                 relief="raised", cursor="hand2", fg="#333", bd=1)
                label.bind("<Button-1>", lambda event, email2=email: self.open_single_email_window(email2))
                label.pack(fill=tk.X)

            self._emails_frame.pack(fill='both', expand=1)
            self._current_filter_state[0] = filter_type

        self._side_menu_frame = tk.Frame(self._emails_frame, bg="#f0f0f0")

        self._side_menu_frame.pack(side='right', fill='y', padx=10, pady=10)

        received_button = tk.Button(self._side_menu_frame, text="Received",
                                    command=lambda: _load_emails('recv'))
        received_button.pack(fill='x', pady=5)

        sent_button = tk.Button(self._side_menu_frame, text="Sent",
                                command=lambda: _load_emails('sent'))
        sent_button.pack(fill='x', pady=5)

        send_email_button = tk.Button(self._emails_frame, text="Send Email",
                                      command=self.open_send_email_window)
        send_email_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

        self._single_email_frame.pack_forget()
        self._send_email_frame.pack_forget()

        _load_emails(self._current_filter_state[0])

    def run(self):
        """
        Starts the GUI event loop.
        """
        self.root.mainloop()

    def receive_emails(self):
        """
        Receives mails in a separate thread.
        """
        try:
            while self._run_receive_thread:
                print('starting')
                code = self._smtp_socket.recv(140)
                code = CryptoService.decrypt_string(code.decode(), self._smtp_key)
                print('thread:', code)
                if code == '-1':
                    print('closing thread')
                    break
                self.root.after(0, lambda code1=code: self.update_gui_with_new_email(code1))
        except socket.error as e:
            print('----------------Thread error-----------------', e)
            self._run_receive_thread = False

    def update_gui_with_new_email(self, email_id):
        """
        Updates the GUI with a new mail.

        Parameters:
        - email_id (str): The new email's mongo id.
        """
        try:
            enc_cmd = CryptoService.encrypt_string('==' + email_id, self._pop3_key)
            self._pop3_socket.send(len(enc_cmd).to_bytes(4, byteorder='big'))
            self._pop3_socket.recv(self._def_enc_len)
            self._pop3_socket.send(enc_cmd)
            self._pop3_socket.recv(self._def_enc_len)
            email_obj_len = int.from_bytes(self._pop3_socket.recv(4), byteorder='big')
            self._pop3_socket.send(self._ack_enc)
            email_dumps = CryptoService.decrypt_obj(self._pop3_socket.recv(email_obj_len), self._pop3_key)
            email_obj: Email = pickle.loads(email_dumps)
            self._pop3_socket.send(self._ack_enc)
        except (socket.error, pickle.PickleError) as e:
            print('--------------------- error in update gui -------------------', e)
            self._pop3_socket.close()
            self.start_pop3_connection(CryptoService.decrypt_string(self._email))
            self.update_gui_with_new_email(email_id)
            return

        if datetime.datetime.now() < email_obj.creation_date or self._current_filter_state[1] is True:
            return

        email_label_text = (f"{email_obj.sender}"
                            f" -> {CryptoService.decrypt_string(email_obj.subject)} | {email_obj.creation_date}")

        new_email_label = tk.Label(self._emails_frame, text=email_label_text, bg="lightgray",
                                   relief="raised", cursor="hand2", fg="#333", bd=1)
        new_email_label.bind("<Button-1>", lambda event, email=email_obj: self.open_single_email_window(email))

        existing_labels = [child for child in self._emails_frame.winfo_children() if isinstance(child, tk.Label)]
        for label in existing_labels:
            label.pack_forget()

        new_email_label.pack(side='top', fill=tk.X)

        for label in existing_labels:
            label.pack(side='top', fill=tk.X)


if __name__ == "__main__":
    user = User()
