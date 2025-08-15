import socket
import uuid
import struct
import threading
from datetime import datetime

DEFAULT_PORT = 1357
HEADER_FORMAT = '<16sBHI' # client_id (16 bytes), version (1 byte), code (2 bytes), payload_size (4 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
USERNAME_LENGTH = 255
KEY_LENGTH = 160  # Length of public key in bytes
VERSION = 1

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
        "MESSAGES_RECEIVED": 2104,
        "ERROR": 9000
    }

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
        # Add a list of made up clients
        self.clients = [
            ClientEntry(id=uuid.uuid4().bytes, username="Alice", public_key=b'\x00' * 160, last_seen=datetime.now()),
            ClientEntry(id=uuid.uuid4().bytes, username="Bob", public_key=b'\x00' * 160, last_seen=datetime.now()),
            ClientEntry(id=uuid.uuid4().bytes, username="Charlie", public_key=b'\x00' * 160, last_seen=datetime.now())
        ]
        self.messages = []
        self.pending_messages = {}

    def run(self):
        port = self.read_port()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("0.0.0.0", port))
        self.server_socket.listen()
        print(f"Server started on port {port}")

        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")

            # Start a new thread to handle the client
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

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

    def handle_client(self, socket: socket.socket):
        while True:
            try:
                # Read header
                header_data = socket.recv(HEADER_SIZE)
                if not header_data:
                    print("Client disconnected.")
                    break

                if len(header_data) < HEADER_SIZE:
                    print("Incomplete header received, closing connection.")
                    break

                # Parse header
                header = struct.unpack(HEADER_FORMAT, header_data)
                payload_size = header[3]

                # Read payload
                payload_data = b""
                if payload_size > 0:
                    payload_data = socket.recv(payload_size)
                        
                    if len(payload_data) < payload_size:
                        print("Incomplete payload received, closing connection.")
                        break

                self.handle_client_message(socket, header, payload_data)

            except Exception as e:
                print(f"Error handling client: {e}")
                break
                
        socket.close()

    def handle_client_message(self, socket: socket.socket, header, payload_data):
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

        code = header[2]

        # Update last seen timestamp
        client_id = header[0]
        for client in self.clients:
            if client.id == client_id:
                client.last_seen = datetime.now()
                break

        if code == REQUEST_CODES["REGISTER"]:
            self.handle_register(socket, header, payload_data)

        elif code == REQUEST_CODES["GET_CLIENTS"]:
            self.handle_get_clients(socket, header) # Empty payload

        elif code == REQUEST_CODES["GET_PUBLIC_KEY"]:
            self.handle_get_public_key(socket, header, payload_data)

        elif code == REQUEST_CODES["SEND_MESSAGE"]:
            self.handle_send_message(socket, header, payload_data)

        elif code == REQUEST_CODES["GET_MESSAGES"]:
            self.handle_get_messages(socket, header) # Empty payload

        else:
            self.send_error_response(socket)

    def handle_register(self, socket: socket.socket, header, payload_data: bytes = b""):
        """
        Register a new user.

        Request format:
        - Username (255 bytes null terminated)
        - Public Key (160 bytes)

        Response format:
        - Client ID (16 bytes)
        """
        if len(payload_data) < USERNAME_LENGTH + KEY_LENGTH:
            self.send_error_response(socket)
            return

        try:
            # Parse payload: username (255 bytes null terminated) + public_key
            username = payload_data[:USERNAME_LENGTH].decode('utf-8').rstrip('\x00')
            public_key = payload_data[USERNAME_LENGTH:]

            # Check if username already exists
            for client in self.clients:
                if client.username == username:
                    self.send_error_response(socket)
                    return

            user_id = uuid.uuid4().bytes
            
            # Add user to client list
            new_client = ClientEntry(user_id, username, public_key, datetime.now())
            self.clients.append(new_client)

            response_header = self.build_response_header(RESPONSE_CODES["REGISTER_SUCCESS"], len(user_id))
            socket.send(response_header)
            
            response_payload = user_id
            socket.send(response_payload)

            print(f"User registered successfully: {username}")

        except Exception as e:
            print(f"Registration error: {e}")
            self.send_error_response(socket)

    def handle_get_clients(self, socket: socket.socket, header):
        """
        Return a list of all connected clients.

        Request format:
        - Header only (empty payload)

        Response format:
        - Version (1 byte)
        - Code (2 bytes)
        - Payload Size (4 bytes)
        - Client List (255 + 16) * num_clients bytes
        """
        client_id = header[0]

        # Build client list
        client_list = bytearray()
        for client in self.clients:
            if client.id == client_id:
                continue  # Skip the requesting client
            client_list.extend(client.id)
            client_list.extend(client.username.encode('utf-8').ljust(USERNAME_LENGTH, b'\x00'))

        response_header = self.build_response_header(RESPONSE_CODES["CLIENT_LIST"], len(client_list))
        socket.send(response_header)

        response_payload = client_list
        socket.send(response_payload)

    def handle_get_public_key(self, socket: socket.socket, header, payload_data: bytes = b""):
        """
        Retrieve the public key of a user.

        Request format:
        - Client ID (16 bytes)

        Response format:
        - Client ID (16 bytes)
        - Public Key (160 bytes)
        """
        if len(payload_data) < 16:
            self.send_error_response(socket)
            return

        client_id = payload_data

        print(f"Retrieving public key for client ID: {client_id}")

        for client in self.clients:
            if client.id == client_id:
                client_key = client.public_key
                response_payload = client_id + client_key

                response_header = self.build_response_header(RESPONSE_CODES["PUBLIC_KEY"], len(response_payload))
                socket.send(response_header)
                socket.send(response_payload)
                print(f"Public key sent for client ID: {client_id}")
                return

        print(f"Client not found: {client_id}")
        self.send_error_response(socket) # Client not found

    def handle_send_message(self, socket: socket.socket, header, payload_data: bytes = b""):
        """
        Handle sending a message to another client.
        
        Request format: 
        - Destination Client ID (16 bytes)
        - Message Type (1 byte)
        - Content Size (4 bytes)
        - Content (variable size, encrypted)
        
        Response format:
        - Client ID (16 bytes)
        - Message ID (4 bytes)
        """
        if len(payload_data) < 21:  # 16 (client_id) + 1 (type) + 4 (content size)
            self.send_error_response(socket)
            return

        to_client_id = payload_data[:16]
        msg_type = payload_data[16]
        message_size = int.from_bytes(payload_data[17:21], byteorder='little')
        content = payload_data[21:]

        # Validate content size
        if len(content) != message_size:
            self.send_error_response(socket)
            return

        # Find recipient
        recipient = None
        for client in self.clients:
            if client.id == to_client_id:
                recipient = client
                break

        if recipient:
            # Add message to message list
            msg_id = len(self.messages) + 1
            from_client = header[0]
            new_message = MessageEntry(msg_id, to_client_id, from_client, msg_type, content)
            self.messages.append(new_message)

            # Add to pending messages
            if to_client_id not in self.pending_messages:
                self.pending_messages[to_client_id] = []
            self.pending_messages[to_client_id].append(new_message)

            response_payload = to_client_id + msg_id.to_bytes(4, byteorder='little')

            # Send success response
            response_header = self.build_response_header(RESPONSE_CODES["MESSAGE_SENT"], len(response_payload))
            socket.send(response_header)

            socket.send(response_payload)
        else:
            self.send_error_response(socket)

    def handle_get_messages(self, socket: socket.socket, header):
        """
        Get pending messages for a client.

        Request format:
        - Header only (empty payload)

        Response format:
        - Messages (variable size):
        - From Client ID (16 bytes)
        - Message ID (4 bytes)
        - Message Type (1 byte)
        - Message Size (4 bytes)
        - Content (variable size, encrypted)
        """
        client_id = header[0]
        
        # Get pending messages for this client
        pending = self.pending_messages.get(client_id, [])
        
        # Prepare response payload
        payload = bytearray()
        
        # Add each message
        for message in pending:
            payload.extend(message.from_client)  # From client ID (16 bytes)
            payload.extend(message.id.to_bytes(4, byteorder='little'))  # Message ID (4 bytes)
            payload.extend(message.type.to_bytes(1, byteorder='little'))  # Type (1 byte)
            payload.extend(len(message.content).to_bytes(4, byteorder='little'))  # Message size
            payload.extend(message.content)  # Message content (encrypted)
        
        # Send response
        response_header = self.build_response_header(RESPONSE_CODES["MESSAGES_RECEIVED"], len(payload))
        socket.send(response_header)
        socket.send(payload)
        
        # Clear pending messages for this client
        if client_id in self.pending_messages:
            self.pending_messages[client_id] = []

    def build_response_header(self, code: int, payload_size: int) -> bytes:
        """
        Build the response header for a message.

        Format:
        - Version (1 byte)
        - Code (2 bytes)
        - Payload Size (4 bytes)
        """
        header = bytearray()
        header.extend(VERSION.to_bytes(1, byteorder='little'))
        header.extend(code.to_bytes(2, byteorder='little'))
        header.extend(payload_size.to_bytes(4, byteorder='little'))
        return header

    def send_error_response(self, socket: socket.socket):
        """
        Send an error response to the client.

        Format:
        - Version (1 byte)
        - Code (2 bytes)
        - Payload Size (4 bytes)
        """
        header = self.build_response_header(RESPONSE_CODES["ERROR"], 0)
        socket.send(header)
        
def main():
    server = Server()
    server.run()

if __name__ == "__main__":
    main()