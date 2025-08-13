import socket
import selectors
import uuid
import struct
from datetime import datetime

DEFAULT_PORT = 1357
HEADER_FORMAT = '<16sBHI'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

class ClientEntry:
    """
    id: 16 byte index
    username: 255 byte username string
    public_key: 160 byte username pkey
    last_seen: user last seen date and time
    """
    def __init__(self, id, username, public_key, last_seen):
        self.id = id
        self.username = username
        self.public_key = public_key
        self.last_seen = last_seen
        
    def update_last_seen(self):
        """Update the last seen timestamp"""
        self.last_seen = datetime.now()
    
    def to_dict(self) -> dict:
        """Convert client to dictionary for serialization"""
        return {
            'id': self.id,
            'username': self.username,
            'public_key': self.public_key,
            'last_seen': self.last_seen
        }
        
class MessageEntry:
    """
    id: 4 bytes index
    to_client: 16 bytes unique recipient ID
    from_client: 16 bytes unique sender ID
    type: 1 byte message type
    content: Blob message content
    """
    def __init__(self, id, to_client, from_client, type, content):
        self.id = id  
        self.to_client = to_client
        self.from_client = from_client
        self.type = type
        self.content = content
        
    def is_for_client(self, client_id: bytes) -> bool:
        """Check if message is for the specified client"""
        return self.to_client == client_id

class Server:
    def __init__(self):
        self.clients = []
        self.messages = []

    def run(self):
        port = self.read_port()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("0.0.0.0", port))
        self.server_socket.listen()
        print(f"Server started on port {port}")

        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")
            self.handle_client(client_socket)

    # Read the port number from a file
    def read_port(self):
        try:
            f = open("myport.info", "r")
            port = int(f.read().strip())
            f.close()
            return port
        except Exception as e:
            print(f"Error reading port: {e}")
            return DEFAULT_PORT

    def handle_client(self, socket):
        try:
            # Read header
            header_data = socket.recv(HEADER_SIZE)
            if not header_data or len(header_data) < HEADER_SIZE:
                print("Incomplete header received, closing connection.")
                return

            # Parse header
            header = struct.unpack(HEADER_FORMAT, header_data)
            payload_size = header[3]

            # Read payload
            payload_data = b""
            if payload_size > 0:
                payload_data = socket.recv(payload_size)
                if len(payload_data) < payload_size:
                    print("Incomplete payload received, closing connection.")
                    return

            print(f"Received header: {header_data}, payload: {len(payload_data)} bytes")
            self.handle_client_message(socket, header, payload_data)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            socket.close()

    def handle_client_message(self, socket, header, payload_data):
        """
        Handle incoming messages from clients.
        Header:
        - 16 bytes: client_id (UUID)
        - 1 byte: version (protocol version)
        - 2 bytes: code (message type)
        - 4 bytes: payload_size (size of the message payload)

        Codes:
          - 600: Register a new user
          - 601: Get a list of all connected clients
          - 602: Get user public key
          - 603: Send a message to another user
          - 604: Retrieve messages for a specific user
        """

        REQUEST_CODES = {
            "REGISTER": 600,
            "GET_CLIENTS": 601,
            "GET_PUBLIC_KEY": 602,
            "SEND_MESSAGE": 603,
            "GET_MESSAGES": 604
        }

        RESPONSE_CODES = {
            "REGISTER_SUCCESS": 2100,
            "CLIENT_LIST": 2101,
            "PUBLIC_KEY": 2102,
            "MESSAGE_SENT": 2103,
            "MESSAGE_RECEIVED": 2104,
            "ERROR": 9000
        }

        client_id = header[0]
        version = header[1]
        code = header[2]
        payload_size = header[3]

        if code == REQUEST_CODES["REGISTER"]:
            self.handle_register(socket, payload_data)

        elif code == REQUEST_CODES["GET_CLIENTS"]:
            self.handle_get_clients(socket)

        elif code == REQUEST_CODES["GET_PUBLIC_KEY"]:
            self.handle_get_public_key(socket, payload_data.decode('utf-8'))

        elif code == REQUEST_CODES["SEND_MESSAGE"]:
            self.handle_send_message(socket, client_id, payload_data)

        elif code == REQUEST_CODES["GET_MESSAGES"]:
            self.handle_get_messages(socket, client_id)

        else:
            socket.send(b"ERROR: Unknown command")

    def handle_register(self, socket: socket.socket, payload_data: bytes):
        if len(payload_data) < 4:
            socket.send(b"ERROR: Invalid registration format")
            return

        # Parse payload: username (255 bytes null terminated) + public_key
        try:
            username = payload_data[:255].decode('utf-8').rstrip('\x00')
            public_key = payload_data[255:]

            # Check if username already exists
            for client in self.clients:
                if client.username == username:
                    socket.send(b"ERROR: Username already exists")
                    return

            # Generate new UUID and create client entry
            client_id = uuid.uuid4().bytes
            new_client = ClientEntry(client_id, username, public_key, datetime.now())
            self.clients.append(new_client)

            socket.send(b"SUCCESS: Registration complete")
            
        except Exception as e:
            print(f"Registration error: {e}")
            socket.send(b"ERROR: Invalid registration format")
            
    def handle_get_clients(self, socket):
        # Return list of clients
        client_list = ""
        for client in self.clients:
            client_list += f"{client.username}|"
        socket.send(f"CLIENTS:{client_list}".encode())

    def handle_get_public_key(self, socket, username):
        for client in self.clients:
            if client.username == username:
                socket.send(f"PUBLIC_KEY:{client.public_key}".encode())
                return
        socket.send(b"ERROR: User not found")

    def handle_send_message(self, socket, client_id, payload_data):
        # Parse message data from payload
        # Expected format: to_client_id(16) + msg_type(1) + content(rest)
        if len(payload_data) < 17:  # at least 16 bytes for ID + 1 byte for type
            socket.send(b"ERROR: Invalid message format")
            return

        to_client_id = payload_data[:16]
        msg_type = payload_data[16]
        content = payload_data[17:]

        # Find recipient
        to_client = None
        for client in self.clients:
            if client.id == to_client_id:
                to_client = client
                break

        if to_client:
            msg_id = len(self.messages) + 1
            new_message = MessageEntry(msg_id, to_client_id, client_id, msg_type, content)
            self.messages.append(new_message)
            socket.send(b"SUCCESS: Message stored")
        else:
            socket.send(b"ERROR: Invalid recipient")

    def handle_get_messages(self, socket, client_id):
        # Get messages for the requesting client
        user_messages = []
        remaining_messages = []

        for msg in self.messages:
            if msg.to_client == client_id:
                user_messages.append(msg)
            else:
                remaining_messages.append(msg)

        # Send messages and remove them from storage
        self.messages[:] = remaining_messages

        response = "MESSAGES:"
        for msg in user_messages:
            response += f"{msg.type}|{msg.content.decode('utf-8', errors='ignore')}|"

        socket.send(response.encode()) 

if __name__ == "__main__":
    server = Server()
    server.run()