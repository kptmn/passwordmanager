import tkinter
from tkinter import messagebox
import threading
import hashlib
import base64
import sys

# Third-party libraries.
from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Local libraries.
import client

class App():

    def __init__(self, HOST, PORT):
        self.app = tkinter.Tk()
        self.app.geometry('560x270')
        #close program when window is closed.
        self.app.protocol('WM_DELETE_WINDOW', self.exit_program)
        self.host = HOST
        self.port = PORT
        self.client = client.Client(self.host, self.port, self)
        # Used for encryption. Only stored in client side.
        self.masterpassword = None
        self.mastername = None
        self.key = None
        self.fernet = None
        self.kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'0',
        iterations=48)
        # For removing from server we keep plain and cipher text.
        self.plain_to_cipher = {}
        # Login window.
        self.loginpage = tkinter.Toplevel()
        #close program when window is closed through login window too.
        self.loginpage.protocol('WM_DELETE_WINDOW', self.exit_program)
        self.loginpage.geometry('350x150')
        self.loginpage.title('Login Window')

        self.loginusernamelabel = tkinter.Label(self.loginpage, text='Username:')
        self.loginusernamelabel.grid(row=0, column=0, padx=15, pady=15)
        self.loginname = tkinter.Entry(self.loginpage)
        self.loginname.grid(row=0, column=1, padx=15, pady=15)

        self.loginpassword = tkinter.Entry(self.loginpage, show='*')
        self.loginpassword.grid(row=1, column=1, padx=10, pady=5)
        self.loginpasswordlabel = tkinter.Label(self.loginpage, text='Password:')
        self.loginpasswordlabel.grid(row=1, column=0, padx=10, pady=5)

        self.loginbutton = tkinter.Button(self.loginpage, text='Login', command=lambda: self.login(self.loginname, self.loginpassword))
        self.loginbutton.grid(row=2, column=0, padx=15, pady=8, sticky='we')
        self.registerbutton = tkinter.Button(self.loginpage, text='Register', command=lambda: self.register(self.loginname, self.loginpassword))
        self.registerbutton.grid(row=2, column=1, padx=15, pady=8, sticky='we')

        # Username block
        self.labelName = tkinter.Label(self.app, text='Adress or Name:')
        self.labelName.grid(row=0, column=0, padx=15, pady=15)
        self.entryName = tkinter.Entry(self.app)
        self.entryName.grid(row=0, column=1, padx=15, pady=15)

        # Password block
        self.labelPassword = tkinter.Label(self.app, text='Password:')
        self.labelPassword.grid(row=1, column=0, padx=10, pady=5)
        self.entryPassword = tkinter.Entry(self.app, show='*')
        self.entryPassword.grid(row=1, column=1, padx=10, pady=5)

        # Add button
        self.buttonAdd = tkinter.Button(self.app, text='Add', command=lambda: self.add(self.entryName, self.entryPassword))
        self.buttonAdd.grid(row=2, column=0, padx=15, pady=8, sticky='we')

        # List Button
        self.buttonList = tkinter.Button(self.app, text='List', command=self.getlist)
        self.buttonList.grid(row=3, column=0, padx=15, pady=8, sticky='we')

        # Remove button
        self.buttonRemove = tkinter.Button(self.app, text='Remove', command=lambda: self.remove(self.entryName))
        self.buttonRemove.grid(row=3, column=1, padx=15, pady=8, sticky='we')

        thread_1 = threading.Thread(target=self.client.listen)
        thread_1.daemon = True
        thread_1.start()
        self.app.withdraw()
        self.app.mainloop()

    def exit_program(self):
        self.app.quit()
        self.app.destroy()
        # Normally when a client is disconnected it doesnt sends disconnect messsage.
        # Its servers job to check for disconnect by seting a timeout limit.
        self.client.message = {'Type': 'Logout'}
        sys.exit()

    def register(self, entryName, entryPassword):
        # accepting input from the user
        username = entryName.get()
        # accepting password input from the user
        password = entryPassword.get()
        if username and password:
            username = hashlib.sha512(username.encode('utf-8')).hexdigest()
            password = hashlib.sha512(password.encode('utf-8')).hexdigest()
            self.client.message = {'Type': 'Register', 'Register':{'entryName': f'{username}',
                                                         'entryPassword': f'{password}'}}
            print(f'Sending {self.client.message}')
        else:
            messagebox.showerror('Error', 'Please fill the both fields')


    def login(self, entryName, entryPassword):
        username = entryName.get()
        self.mastername = username
        password = entryPassword.get()
        self.masterpassword = password
        if username and password:
            username = hashlib.sha512(username.encode('utf-8')).hexdigest()
            password = hashlib.sha512(password.encode('utf-8')).hexdigest()
            self.client.message = {'Type': 'Login', 'Login':{'entryName': username, 'entryPassword': password}}
        else:
            messagebox.showerror('Error', 'Please fill the both fields')

    def showmessage(self, message):
        if message['Message1'] == 'Error':
            messagebox.showerror('Error', f"{message['Message2']}")
        elif message['Message1'] == 'Login':
            print('Removing register screen')
            self.app.title(self.mastername)
            self.app.deiconify()
            self.loginpage.destroy()
            _ = self.mastername + self.masterpassword
            self.key = hashlib.sha256(_.encode('utf-8')).digest()
            self.key = base64.urlsafe_b64encode(self.kdf.derive(self.key))
            self.fernet = fernet.Fernet(self.key)
            print(f'Your unique key is {self.key}')
        elif message['Message1'] == 'Getlist':
            pairs = {}
            self.plain_to_cipher = {}
            for i in message['Message2']:
                value = message['Message2'][i]
                value = value[2:-1].encode('utf-8')
                # Quick fix for a small bug.
                cipher_text = i[2:-1].encode('utf-8')
                i = self.fernet.decrypt(cipher_text).decode()
                self.plain_to_cipher[i] = cipher_text
                value = self.fernet.decrypt(value).decode()
                pairs[i] = value
            messagebox.showinfo('pairs', pairs)
        else:
            messagebox.showinfo(f"{message['Message1']}", f"{message['Message2']}")

    def add(self, entryName, entryPassword):
        # accepting input from the user
        username = entryName.get()
        # accepting password input from the user
        password = entryPassword.get()
        if username and password:
            username = self.fernet.encrypt(username.encode('utf-8'))
            password = self.fernet.encrypt(password.encode('utf-8'))
            self.special = username
            self.client.message = {'Type': 'Add', 'Add':{'entryName': f'{username}',
                                                         'entryPassword': f'{password}'}}
            print(f'Sending {self.client.message}')
        else:
            messagebox.showerror('Error', 'Please fill the both fields')

    def getlist(self):
        # creating a dictionary
        self.client.message = {'Type': 'Getlist'}

    def remove(self, entryName):
        # accepting input from the user
        plain_text = entryName.get()
        try:
            username = self.plain_to_cipher[plain_text]
            self.client.message = {'Type': 'Remove', 'Remove':{'entryName': f'{username}'}}
        except:
            self.showmessage({'Message1':'Error', 'Message2':f'Could not find {plain_text}, please list elements first and try again.'})
