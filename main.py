import datetime
import tkinter as tk
from tkinter import messagebox
import re
import DataBaseServer
from Mail import Mail
from User import User
from CustomLabel import CustomLabel


def is_valid_password(password) -> bool:
    password_pattern = r"^[a-zA-Z0-9\-_\.!@#$%]{11,16}$"
    return re.match(password_pattern, password) is not None


def is_valid_username(username) -> bool:
    username_pattern = r"^[a-zA-Z0-9\-_\.]{5,16}$"
    return re.match(username_pattern, username) is not None


def is_valid_email(email) -> bool:
    return email.endswith('@mun.com') and is_valid_username(email[:email.rfind('@')])


def login():
    email = email_entry.get()
    password = password_entry.get()
    isValidEmail = is_valid_email(email)
    isValidPassword = is_valid_password(password)
    if isValidEmail and isValidPassword:
        messagebox.showinfo("Login", f"Logged in with email: {email}")
        db = DataBaseServer.DataBaseService()
        user: User = DataBaseServer.mongo_obj_to_User(db.authenticate_user(email, password))

        if user is None:
            messagebox.showerror("Login failed!", "Please try again")
        else:
            messagebox.showinfo("Successfull log in!", f"Hey {user.first_name}! welcome to MailUN")
            # open_mail_page(user)
            loginPage.destroy()
            registerPage.destroy()
            print("ANS IS:", db.email_to_mongo_obj("danny.umansky@mun.com"))
            open_mails_window(None)
            mails = db.get_all_received_mails(user.email)
            labels = [f"{mail.get('sender').get('email')} -> {mail.get('subject')} | {mail.get('creation_date')}" for
                      mail in mails]

            for label_text, mail in zip(labels, mails):
                label = CustomLabel(mails_frame, mongoID="12345", text=label_text, bg="lightgray", relief="raised",
                                    cursor="hand2")
                print("mail:", mail, label_text)
                label.bind("<Button-1>", lambda event, mail2=mail: open_single_mail_window(mail2))
                label.pack(fill=tk.X)
            send_mail_button = tk.Button(mails_frame, text="Send Mail",
                                         command=lambda event=user.email: open_send_mail_window(event))
            send_mail_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

    elif isValidEmail:
        messagebox.showerror("Error", "Invalid password format")
    elif isValidPassword:
        messagebox.showerror("Error", "Invalid email format")
    else:
        messagebox.showerror("Error", "Invalid password and email formats")


def open_send_mail_window(email):
    global mails_frame, send_mail_recipients_label, send_mail_recipients_entry, send_mail_subject_label, \
        send_mail_subject_entry, send_mail_message_label, send_mail_message_text, send_mail_send_button
    mails_frame.pack_forget()
    # Recipients
    send_mail_recipients_label = tk.Label(root, text="Recipients:")
    send_mail_recipients_label.pack()

    send_mail_recipients_entry = tk.Entry(root)
    send_mail_recipients_entry.pack(fill="x")

    # Subject
    send_mail_subject_label = tk.Label(root, text="Subject:")
    send_mail_subject_label.pack()

    send_mail_subject_entry = tk.Entry(root)
    send_mail_subject_entry.pack(fill="x")

    # Message
    send_mail_message_label = tk.Label(root, text="Message:")
    send_mail_message_label.pack()

    send_mail_message_text = tk.Text(root, height=10, width=40)
    send_mail_message_text.pack()

    # Send Button
    send_mail_send_button = tk.Button(root, text="Send", command=lambda event=email: send_mail(event))
    send_mail_send_button.pack()


def send_mail(fromUser: User):
    global send_mail_recipients_entry

    emails: str = send_mail_recipients_entry.get()
    realEmails = [i for i in emails.split(',') if i != ""]
    print(f"mail sent from {fromUser.email} to: {realEmails}")
    db = DataBaseServer.DataBaseService()
    recipients = [DataBaseServer.mongo_obj_to_User(db.email_to_mongo_obj(email)) for email in realEmails]
    sendEmail = Mail(fromUser,recipients, send_mail_subject_entry.get(), send_mail_message_text.get("1.0", 'end-1c'),
                     datetime.datetime.now())
    fromUser.send_email()
    print("EMAIL SENT NOW!!")


# noinspection PyUnresolvedReferences
def register():
    email = email_entry.get()
    password = password_entry.get()

    if is_valid_email(email):
        messagebox.showinfo("Register", f"Registered with email: {email}")
        # Add your registration logic here
    else:
        messagebox.showerror("Error", "Invalid email format")


def open_registerPage():
    registerPage.pack(fill='both', expand=1)
    loginPage.forget()


def open_loginPage():
    loginPage.pack(fill='both', expand=1)
    registerPage.forget()


def on_label_click(event):
    label = event.widget.cget("text")
    print(f"Clicked label: {label}")


def open_single_mail_window(mail):
    global mails_frame, single_mail_frame
    # Clear existing labels in newFrame
    for widget in single_mail_frame.winfo_children():
        widget.destroy()
    # change to set mail from DB, use Mail class
    single_mail_frame_label = tk.Label(single_mail_frame, text=mail.get('message'), bg="lightgray", relief="raised")
    single_mail_frame_label.pack(fill=tk.X)
    single_mail_frame_label.bind("<Button-1>", open_mails_window)
    mails_frame.pack_forget()
    single_mail_frame.pack(fill='both', expand=1)


def open_mails_window(e):
    mails_frame.pack(fill='both', expand=1)
    single_mail_frame.pack_forget()


def initializeLoginPage():
    global email_label, email_entry, password_label, password_entry, login_button, register_button
    email_label = tk.Label(loginPage, text="Email", bg="#f0f0f0")
    email_label.pack(pady=10)

    email_entry = tk.Entry(loginPage, width=30, font=("Helvetica", 12))
    email_entry.pack(pady=5)

    password_label = tk.Label(loginPage, text="Password:", bg="#f0f0f0")
    password_label.pack(pady=10)

    password_entry = tk.Entry(loginPage, show="•", width=30, font=("Helvetica", 12))
    password_entry.pack(pady=5)

    login_button = tk.Button(loginPage, text="Login", command=login, bg="#4caf50", fg="white", width=20,
                             font=("Helvetica", 12))
    login_button.pack(pady=10)

    register_button = tk.Button(loginPage, text="Register", command=open_registerPage, bg="#2196F3", fg="white",
                                width=20,
                                font=("Helvetica", 12))
    register_button.pack()


def initializeRegisterPage():
    global registration_label_register, email_label_register, email_entry_reg_register, password_label_register, password_entry_reg_register, first_name_label_register, first_name_entry_register, \
        last_name_label_register, last_name_entry_register, birth_date_label_register, birth_date_entry_register, register_button_register, login_button1
    registration_label_register = tk.Label(registerPage, text="Registration Form", font=("Helvetica", 16))
    registration_label_register.pack(pady=10)

    email_label_register = tk.Label(registerPage, text="Email (****@mun.com):")
    email_label_register.pack()

    email_entry_reg_register = tk.Entry(registerPage, width=30)
    email_entry_reg_register.pack()

    password_label_register = tk.Label(registerPage, text="Password:")
    password_label_register.pack()

    password_entry_reg_register = tk.Entry(registerPage, show="•", width=30)
    password_entry_reg_register.pack()

    first_name_label_register = tk.Label(registerPage, text="First Name:")
    first_name_label_register.pack()

    first_name_entry_register = tk.Entry(registerPage, width=30)
    first_name_entry_register.pack()

    last_name_label_register = tk.Label(registerPage, text="Last Name:")
    last_name_label_register.pack()

    last_name_entry_register = tk.Entry(registerPage, width=30)
    last_name_entry_register.pack()

    birth_date_label_register = tk.Label(registerPage, text="Birth Date (DD-MM-YYYY):")
    birth_date_label_register.pack()

    birth_date_entry_register = tk.Entry(registerPage, width=30)
    birth_date_entry_register.pack()

    register_button_register = tk.Button(registerPage, text="Submit", command=register, bg="#4caf50", fg="white",
                                         width=20,
                                         font=("Helvetica", 12))
    register_button_register.pack(pady=10)

    login_button1 = tk.Button(registerPage, text="Login", command=open_loginPage, bg="#2196F3", fg="white", width=20,
                              font=("Helvetica", 13))

    login_button1.pack(pady=10)


root = tk.Tk()
root.title("Login Page")

root.geometry("500x500")
root.configure(bg="#f0f0f0")

loginPage = tk.Frame(root)
registerPage = tk.Frame(root)
registration_label_register = None
email_label_register = None
email_entry_reg_register = None
password_label_register = None
password_entry_reg_register = None
first_name_label_register = None
first_name_entry_register = None
last_name_label_register = None
last_name_entry_register = None
birth_date_label_register = None
birth_date_entry_register = None
register_button_register = None
login_button1 = None
email_label = None
email_entry = None
password_label = None
password_entry = None
login_button = None
register_button = None
send_mail_recipients_label = None
send_mail_recipients_entry = None
send_mail_subject_label = None
send_mail_subject_entry = None
send_mail_message_label = None
send_mail_message_text = None
send_mail_send_button = None
single_mail_frame = tk.Frame(root)
mails_frame = tk.Frame(root)
initializeLoginPage()
initializeRegisterPage()
loginPage.pack(fill="both", expand=1)
root.mainloop()
