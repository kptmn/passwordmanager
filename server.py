import socketserver
import struct
import json

class Serializer(json.JSONEncoder):
    def default(self, o):
        return int(o)

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

class Handler(socketserver.BaseRequestHandler):

    def setup(self) -> None:
        # For queuing messages to send.
        # Recieved at the client side and messages are shown to user as pop-up messages by using message box.
        self.queued_data = []
        # For keeping which IP logged in as who, granting acces to them, to their own passwords.
        # Users can access only to their own password.
        self.online_users = {}
        
        return super().setup()

    def add(self, data, client_IP, client_PORT):
        user_ID = self.online_users[f"{client_IP}, {client_PORT}"]
        entryName = data["entryName"]
        entryPassword = data["entryPassword"]
        with open(f"{user_ID[0]}.txt", 'a') as f:
            f.write(f"{entryName} {entryPassword}\n")
        self.queued_data.append({
            "Type":"Message",
            "Message":{"Message1":"Success",
                        "Message2":"Password added!"},
        })

    def getlist(self, client_IP, client_PORT):
        # creating a dictionary
        passwords = {}
        user_ID = self.online_users[f"{client_IP}, {client_PORT}"]
        # adding a try block, this will catch errors such as an empty file or others
        try:
            with open(f"{user_ID[0]}.txt", 'r') as f:
                for k in f:
                    i = k.split(' ')
                    passwords[i[0]] = i[1]
        except:
            print("No passwords found!!")

        if passwords:
            mess = "List of passwords:\n"
            pairs = {}
            for name, password in passwords.items():
                # generating a proper message
                mess += f"Password for {name} is {password}\n"
                pairs[name] = password[:-1]
            # Showing the message
            self.queued_data.append({
                "Type":"Message",
                "Message":{"Message1":"Getlist",
                           "Message2":pairs},
            })
        else:
            self.queued_data.append({
                "Type":"Message",
                "Message":{"Message1":"Paswords",
                           "Message2":"Empty list!"},
            })

    def remove(self, data, client_IP, client_PORT):
        # accepting input from the user
        username = data["entryName"]
        user_ID = self.online_users[f"{client_IP}, {client_PORT}"]

        changed_file = False

        # creating a temporary list to store the data
        temp_passwords = []

        # reading data from the file and excluding the specified username
        try:
            with open(f"{user_ID[0]}.txt", 'r') as f:
                for k in f:
                    i = k.split(' ')
                    if i[0] != username:
                        print(i[0], username, len(i[0]), len(username))
                        temp_passwords.append(f"{i[0]} {i[1]}")
                    else:
                        changed_file = True

            # writing the modified data back to the file
            with open(f"{user_ID[0]}.txt", 'w') as f:
                for line in temp_passwords:
                    f.write(line)
            if changed_file:
                self.queued_data.append({
                    "Type":"Message",
                    "Message":{"Message1":"Success",
                            "Message2":f"password for {username} removed successfully!"},
                            })
            else:
                self.queued_data.append({
                    "Type":"Message",
                    "Message":{"Message1":"Error",
                            "Message2":f"password for {username} can not found!"},
                            })
        except Exception as e:
            self.queued_data.append({
                "Type":"Message",
                "Message":{"Message1":"Error",
                           "Message2":f"Error removing password for {username}: {e}"},
                           })

    def send_payload(self):
        serialized = self.serializer.encode(self.queued_data).encode("utf-8")
        self.queued_data = []
        response_payload = struct.pack("<i", len(serialized)) + serialized
        print(f"Sending {serialized}")
        self.request.sendall(response_payload)

    def process_packet(self, packet, client_IP, client_PORT):
        if packet["Type"] == "Add":
            self.add(packet["Add"], client_IP, client_PORT)
        elif packet["Type"] == "Getlist":
            self.getlist(client_IP, client_PORT)
        elif packet["Type"] == "Remove":
            self.remove(packet["Remove"], client_IP, client_PORT)
        elif packet["Type"] == "Login":
            print("Logging...")
            self.check_login(packet["Login"], client_IP, client_PORT)
        elif packet["Type"] == "Register":
            self.register(packet["Register"])
        elif packet["Type"] == "Logout":
            # Disconnect user when they logout.
            self.online_users.pop((f"{client_IP}, {client_PORT}"))

    def register(self, data):
        # Not works if registered users is empty or non existent.
        entryName = data["entryName"]
        entryPassword = data["entryPassword"]
        # Check if username already exists.
        passwords = {}
        with open("registered_users.txt", 'r') as f:
            for k in f:
                i = k.split(' ')
                # creating the key-value pair of username and password.
                passwords[i[0]] = i[1]

        if passwords:
            no_username_is_found = True
            for i in passwords:
                if i == entryName:
                    no_username_is_found = False
                    self.queued_data.append({"Type":"Message",
                                             "Message":{"Message1":"Error",
                                                        "Message2":"Username already in use! Try again."}})
                    break

        if no_username_is_found:
            with open("registered_users.txt", 'a') as f:
                f.write(f"{entryName} {entryPassword}\n")
            self.queued_data.append({
                "Type":"Message",
                "Message":{"Message1":"Success",
                            "Message2":"Registered a new user!"},
            })

    def check_login(self, data, client_IP, client_PORT):
        username = data["entryName"]
        password  = data["entryPassword"]

        # creating a dictionary to store the data in the form of key-value pairs
        passwords = {}
        # opening the text file
        # requires registered_users.txt must already exist
        with open("registered_users.txt", 'r') as f:
            for k in f:
                i = k.split(' ')
                # creating the key-value pair of username and password.
                passwords[i[0]] = i[1]

        if passwords:
            no_username_is_found = True
            for i in passwords:
                if i == username:
                    no_username_is_found = False
                    # Strip is required or its shown with new line.
                    if password == passwords[i].strip():
                        self.queued_data.append({"Type":"Message", "Message":{"Message1":"Login"}})
                        # Pair Login and Socket so its individual and secure.
                        self.online_users[f"{client_IP}, {client_PORT}"] = (username, password)
                    else:
                        self.queued_data.append({"Type":"Message",
                                                 "Message":{"Message1": "Retry",
                                                            "Message2": "Wrong Password!"}})
                    break
            if no_username_is_found:
                self.queued_data.append({"Type":"Message",
                                         "Message":{"Message1":"Register First!",
                                                    "Message2":"No such registered user!"}})
        else:
            self.queued_data.append({"Type":"Message",
                                         "Message":{"Message1":"Empty Register list!",
                                                    "Message2":"No Registered users!"}})

    def read_packet(self):
        header = self.request.recv(4)
        # Get IP and PORT of connection to verify after login.
        # Because server and client are runing on the same computer, all the ip adresses -including server- are the same.
        client_IP, client_PORT = self.client_address
        if not header:
            return None
        (body_size,) = struct.unpack("<i", header)
        data = self.request.recv(body_size)
        print(f"Got data {data}")
        return json.loads(data.decode("utf-8")), client_IP, client_PORT

    def handle(self):
        self.serializer = Serializer()
        while True:
            if self.queued_data != []:
                self.send_payload()
            packet, client_IP, client_PORT = self.read_packet()
            if packet is None:
                break
            try:
                self.process_packet(packet, client_IP, client_PORT)
            except:
                pass

def main(HOSTNAME, PORT):
    server = Server((HOSTNAME, PORT), Handler)
    try:
        server.serve_forever()
    except:
        pass

main("127.0.0.1", 9111)
