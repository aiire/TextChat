import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import errno
import random
from typing import Optional

from common import *

class ChatClient:
    def __init__(self, master: tk.Tk):
        self.master = master # Store the root widget
        self.master.title('Chat Client')  # Set the title of the GUI window to 'Chat Server'

        self.main_frame = tk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.left_frame = tk.Frame(self.main_frame)
        self.left_frame.pack(side=tk.LEFT, anchor='n', padx=(0, 10))  # Align to top-left

        self.right_frame = tk.Frame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)  # Chat expands to fill space

        self.host_frame = tk.Frame(self.left_frame)
        self.host_frame.pack(anchor='w', pady=(0, 10))
        self.host_label = tk.Label(self.host_frame, text='Server Host')
        self.host_label.pack(side=tk.LEFT)
        self.host_var = tk.StringVar(master, value=DEFAULT_HOST)
        self.host_entry = tk.Entry(self.host_frame, textvariable=self.host_var, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 0))  # Spacing between label and entry

        # Row 2: Port Label and Entry
        self.port_frame = tk.Frame(self.left_frame)
        self.port_frame.pack(anchor='w', pady=(0, 10))
        self.port_label = tk.Label(self.port_frame, text='Server Port')
        self.port_label.pack(side=tk.LEFT)
        self.port_var = tk.IntVar(master, value=DEFAULT_PORT)
        self.port_entry = tk.Entry(self.port_frame, textvariable=self.port_var, width=20)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 0))

        # Button to connect to a server (if not already connected to one)
        self.connect_button = tk.Button(self.left_frame, text='Connect', command=self.connect)
        self.connect_button.pack(anchor='w', pady=(0, 10))
        
        # Add a button to disconnected from the active server
        self.disconnect_button = tk.Button(self.left_frame, text='Disconnect', command=self.disconnect)
        self.disconnect_button.pack(anchor='w', pady=(0, 10))
        self.disconnect_button.config(state=tk.DISABLED)

        # Listbox for connected users
        self.user_list_label = tk.Label(self.left_frame, text='Connected Users')
        self.user_list_label.pack(anchor='w', pady=(0, 5))
        self.user_listbox = tk.Listbox(self.left_frame, width=25, height=15)
        self.user_listbox.pack(anchor='w', pady=(0, 10))

        # And add a button to stop the server
        self.chat_area = scrolledtext.ScrolledText(self.right_frame, wrap=tk.NONE, state=tk.DISABLED, width=70, height=20)
        self.chat_area.pack(fill=tk.BOTH, pady=(0, 10), expand=True)

        # Frame to hold the message entry and send button
        self.message_frame = tk.Frame(self.right_frame)
        self.message_frame.pack(fill=tk.BOTH, pady=(0, 10))
        self.message_var = tk.StringVar(master)  # Changed from IntVar to StringVar for text input
        self.message_entry = tk.Entry(self.message_frame, textvariable=self.message_var, width=60)
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_entry.config(state=tk.DISABLED)
        self.message_entry.bind('<Return>', self.send_message)

        # Send Button
        self.send_button = tk.Button(self.message_frame, text='Send', command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.send_button.config(state=tk.DISABLED)

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_connected = False

        self.nickname = None
        self.ask_nick()
        
    # Ask user for a nickname
    def ask_nick(self):
        while not self.nickname:
            number = random.randint(1, 100)
            default_nick = f'Guest{number}'
            self.nickname = simpledialog.askstring('Nickname', 'Please choose a nickname', initialvalue=default_nick, parent=self.master).strip()
    
    # Attempt to connect to the server at the specified address
    def connect(self):
        if self.is_connected:
            return
        
        # Ask the user for a nickname if not already set
        self.ask_nick()
        
        if not self.client:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # Retrieve host and port
            host = self.host_var.get()
            port = self.port_var.get()

            # Attempt connection
            self.client.connect((host, port))
            self.display_message(f"Established connection with {host}:{port}")

            # The server may send 'NICK' as a request for the nickname
            initial_message = self.client.recv(1024).decode()
            if initial_message == 'NICK':
                self.client.sendall(self.nickname.encode())

            # Enable 'Connect' button and disable 'Disconnect' button
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)

            # Enable 'Send' button and the message entry
            self.send_button.config(state=tk.NORMAL)
            self.message_entry.config(state=tk.NORMAL)

            # Disable 'Server Host' and 'Server Port' entries
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)

            self.is_connected = True

            # Start thread to continuously receive messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()

        except socket.gaierror:
            # Typically raised for address-related errors (invalid hostname)
            messagebox.showerror('Hostname Error', 'Invalid server address. Please enter a valid host.')
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                messagebox.showerror('Connection Error', 'Failed to connect: Connection refused by the server.')
            else:
                messagebox.showerror('Socket Error', f'Failed to connect to server:\n{e}')
        except Exception as e:
            messagebox.showerror('Unexpected Error', f'An unexpected error occurred:\n{e}')
        finally:
            if not self.is_connected:
                self.client = None

    def disconnect(self, reason=None):
        if not self.is_connected:
            return
        
        # Attempt to notify the server that we wish to disconnect
        try:
            self.send_packet(encode_packet({'type': 'user_disconnect', 'user': self.nickname}))
        except:
            pass
        
        # Close the socket and reset variables
        self.is_connected = False
        self.client.close()
        self.client = None
        self.nickname = None

        # Enable 'Connect' button and disable 'Disconnect' button
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)

        # Disable 'Send' button and the message text entry
        self.send_button.config(state=tk.DISABLED)
        self.message_entry.config(state=tk.DISABLED)

        # Enable 'Server Host' and 'Server Port' entries
        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)

        # Clear all messages printed in chat
        self.chat_area.config(state=tk.NORMAL) # Enable editing first
        self.chat_area.delete('1.0', tk.END)
        self.chat_area.config(state=tk.DISABLED)

        self.update_user_list([]) # Clear user list

        if reason:
            messagebox.showinfo('Connection Lost', reason)


    def update_user_list(self, nicknames: list[str]):
        self.user_listbox.delete(0, tk.END)
        for nickname in nicknames:
            # If this is your name, make it obvious to the user
            if nickname == self.nickname:
                nickname += ' (You)'
            self.user_listbox.insert(tk.END, nickname)
        
    # Listens for messages from the server and updates the chat text box
    def receive_messages(self):
        while self.is_connected:
            try:
                packet = self.client.recv(1024)
                packet_data = json.loads(packet.decode()) # Parse the incoming JSON data
                packet_type = packet_data['type']

                if packet_type in ['user_connected', 'user_disconnected']:
                    # Update the user list box according to who is currently online
                    self.update_user_list(packet_data['user_list'])

                    # Print a message saying '[user] has joined the chat.'
                    if packet_type == 'user_connected':
                        self.display_message(f'{packet_data['user']} has joined the chat.')
                    else:
                        self.display_message(f'{packet_data['user']} has left the chat.')

                elif packet_type == 'user_message':
                    # Print the received message to the user's chat window
                    sender = packet_data['sender']
                    message = packet_data['content']
                    self.display_message(f'({sender}) {message}')
                elif packet_type == 'server_message':
                    # Print the received message to the user's chat window
                    message = packet_data['content']
                    self.display_message(f'[SERVER] {message}')
                elif packet_type == 'server_closed':
                    # Disconnect from the server now that it's closing
                    self.disconnect(reason='Server closed.')
                    break
                else:
                    self.display_message(f'[SERVER] {packet_data}')
            
            except Exception as e:
                self.disconnect(reason=str(e))
                break

    # Displays a message in the chat area
    def display_message(self, message: str):
        print(message)
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + '\n') # Insert the message at the end
        self.chat_area.see(tk.END)  # Auto-scroll to the new message
        self.chat_area.config(state=tk.DISABLED)  # Prevent user edits
    
    def send_packet(self, packet: bytes):
        # self.display_message(f'Sending {packet.decode()}')
        self.client.sendall(packet)

    # Sends the message from the text entry widget to the server
    def send_message(self, event=None):
        message = self.message_entry.get()
        if message:
            self.send_packet(encode_packet({'type': 'user_message', 'sender': self.nickname, 'content': message}))
            self.message_entry.delete(0, tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()
