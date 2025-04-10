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
        self.master.title('Chat Client')  # Set the title of the GUI window to 'Chat Client'
        
        self.setup_gui()

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_running = False
        self.client_id = None
        self.nickname = None
        # self.ask_nick()

        self.blocked_users = read_file('blocked_users.json', [])
        
    def setup_gui(self):
        master = self.master

        main_frame = tk.Frame(master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, anchor='n')  # Align to top-left

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)  # Chat expands to fill space

        # Register the validation function for number-only text entries
        validate_number = master.register(lambda P: P.isdigit() or P == '')

        # Allow the user to specify the chat room hostname
        host_frame = tk.Frame(left_frame)
        host_frame.pack(anchor='w', pady=(0, 10))
        host_label = tk.Label(host_frame, text='Host')
        host_label.pack(side=tk.LEFT)
        self.host_var = tk.StringVar(master, name='SERVER_HOST', value=DEFAULT_HOST)
        self.host_var.trace_add('write', self.on_address_change)  # Triggers when text changes
        self.host_entry = tk.Entry(host_frame, textvariable=self.host_var, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 0))  # Spacing between label and entry

        # Allow the user to enter the port 
        port_frame = tk.Frame(left_frame)
        port_frame.pack(anchor='w', pady=(0, 10))
        port_label = tk.Label(port_frame, text='Port')
        port_label.pack(side=tk.LEFT)
        self.port_var = tk.IntVar(master, name='SERVER_PORT', value=DEFAULT_PORT)
        self.port_var.trace_add('write', self.on_address_change)  # Triggers when text changes
        self.port_entry = tk.Entry(port_frame, validate='key', validatecommand=(validate_number, '%P'), textvariable=self.port_var, width=20)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 0))

        # Create a frame for the buttons to keep them on the same line
        button_frame = tk.Frame(left_frame)
        button_frame.pack(anchor='w', pady=(0, 10))  # Packs the frame in left_frame

        # Add a button to join the chat room
        self.join_button = tk.Button(button_frame, text='Join', command=self.start_client)
        self.join_button.pack(side=tk.LEFT, padx=(0, 10))  # Left alignment with padding

        # Add a button to leave the chat room (if connected to one)
        self.leave_button = tk.Button(button_frame, text='Leave', command=self.stop_client)
        self.leave_button.pack(side=tk.LEFT)  # Left alignment next to start button
        self.leave_button.config(state=tk.DISABLED)

        # Listbox for connected users
        # Create a frame for the listbox and scrollbar together
        list_frame = tk.Frame(left_frame)
        list_frame.pack(anchor='w', pady=(0, 10))

        # Label remains above the list_frame
        user_list_label = tk.Label(list_frame, text='Users Online')
        user_list_label.pack(anchor='w', pady=(0, 5))

        # Create the listbox inside the frame
        self.user_listbox = tk.Listbox(list_frame, width=25, height=12)
        self.user_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

        # Create and attach the scrollbar to the listbox within the same frame
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.user_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Connect the listbox to the scrollbar
        self.user_listbox.config(yscrollcommand=scrollbar.set)
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_select)

        # Let the user block annoying users
        self.block_button = tk.Button(left_frame, text='Block', command=self.block_user)
        self.block_button.pack(side=tk.LEFT, padx=(0, 10))
        self.block_button.config(state=tk.DISABLED)

        # You can unblock blocked users as well
        self.unblock_button = tk.Button(left_frame, text='Unblock', command=self.unblock_user)
        self.unblock_button.pack(side=tk.LEFT, padx=(0, 10))
        self.unblock_button.config(state=tk.DISABLED)

        # Add the report button
        self.report_button = tk.Button(left_frame, text='Report', command=self.report_user)
        self.report_button.pack(side=tk.LEFT)
        self.report_button.config(state=tk.DISABLED)

        # And add a button to stop the server
        self.chat_area = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, state=tk.DISABLED, width=60, height=20)
        self.chat_area.pack(fill=tk.BOTH, pady=(0, 10), expand=True)

        # Frame to hold the message entry and send button
        message_frame = tk.Frame(right_frame)
        message_frame.pack(fill=tk.BOTH, pady=(0, 10))
        self.message_var = tk.StringVar(master)  # Changed from IntVar to StringVar for text input
        self.message_var.trace_add('write', self.on_message_typed)
        self.message_entry = tk.Entry(message_frame, textvariable=self.message_var, width=60)
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_entry.config(state=tk.DISABLED)
        self.message_entry.bind('<Return>', self.send_message)

        # Send Button
        self.send_button = tk.Button(message_frame, text='Send', command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.send_button.config(state=tk.DISABLED)

    # Ask user for a nickname
    def ask_nick(self):
        while not self.nickname:
            number = random.randint(1, 100)
            default_nick = f'Guest{number}'
            self.nickname = simpledialog.askstring('Nickname', 'Please choose a nickname', initialvalue=default_nick, parent=self.master)
        self.nickname = self.nickname.strip()
    
    # Attempt to connect to the server at the specified address
    def start_client(self):
        if self.client_running:
            return

        self.ask_nick()

        if not self.client:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Retrieve host and port entered by the user
            host = self.host_var.get()
            port = self.port_var.get()

            # Attempt at connecting
            self.client.connect((host, port))
            self.send_packet(encode_packet({'type': 'user_connected', 'nick': self.nickname}))

            # Wait for server's response and decode it
            response = decode_packet(self.client.recv(1024))
            response_type = response.get('type')
            response_status = response.get('status')

            if response_type == 'connection_ack':
                self.client_id = response.get('your_id')
                self.display_message(f'Established connection with {host}:{port}')
                self.send_packet(encode_packet({'type': 'user_joined', 'nick': self.nickname}))

            elif response_type == 'connection_error':
                reason = response.get('reason')
                if response_status == 'banned':
                    self.stop_client()
                    messagebox.showwarning('Forbidden', f'You are banned from this server.\nReason: {reason}')
                    return
                if response_status == 'nick_taken':
                    self.stop_client()
                    messagebox.showwarning('Nickname Taken', reason)
                    return
                
                self.stop_client()
                messagebox.showwarning('Connection Error', f'Failed to connect to server: {reason}')
                return
            else:
                raise Exception(f'Received invalid packet of type "{response_type}".')

            # Update UI configuration in one block after successful connection
            self.join_button.config(state=tk.DISABLED)
            self.leave_button.config(state=tk.NORMAL)
            # self.send_button.config(state=tk.NORMAL)
            self.message_entry.config(state=tk.NORMAL)
            # self.block_button.config(state=tk.NORMAL)
            # self.unblock_button.config(state=tk.NORMAL)
            # self.report_button.config(state=tk.NORMAL)
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.client_running = True

            # Start thread to continuously receive messages
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

        except socket.gaierror:
            messagebox.showwarning('Hostname Error', 'Invalid server address. Please enter a valid host.')
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                messagebox.showwarning('Connection Error', 'Failed to connect: Connection refused by the server.')
            else:
                messagebox.showwarning('Socket Error', f'Failed to connect to server:\n{e}')
        except Exception as e:
            messagebox.showerror('Unexpected Error', f'An unexpected error occurred:\n{e}')

        if not self.client_running:
            self.stop_client()

    def stop_client(self, reason=None):
        # Attempt to notify the server that we wish to disconnect
        try:
            self.send_packet(encode_packet({'type': 'user_disconnect', 'user': self.nickname}))
        except:
            pass
        
        # Close the socket and reset variables
        self.client_running = False
        if self.client:
            self.client.close()
            self.client = None
        self.nickname = None

        # Enable 'Connect' button and disable 'Disconnect' button
        self.join_button.config(state=tk.NORMAL)
        self.leave_button.config(state=tk.DISABLED)

        # Disable 'Send' button and the message text entry
        self.send_button.config(state=tk.DISABLED)
        self.message_entry.config(state=tk.DISABLED)

        # Enable 'Server Host' and 'Server Port' entries
        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
            
        # Disable 'Block' and 'Report' button
        self.block_button.config(state=tk.DISABLED)
        self.unblock_button.config(state=tk.DISABLED)
        self.report_button.config(state=tk.DISABLED)

        # Clear all messages printed in chat
        self.chat_area.config(state=tk.NORMAL) # Enable editing first
        self.chat_area.delete('1.0', tk.END)
        self.chat_area.config(state=tk.DISABLED)

        self.update_user_list() # Clear user list

        if reason:
            self.display_message(f'Connection Lost: {reason}')

    # Executes when the host selects a user in the user list 
    def on_user_select(self, event=None):
        selection = self.user_listbox.curselection()

        # If there is no user selected, disable user safety buttons
        if not selection:
            self.block_button.config(state=tk.DISABLED)
            self.unblock_button.config(state=tk.DISABLED)
            self.report_button.config(state=tk.DISABLED)
            self.selected_user = None
            return

        index = selection[0]
        self.selected_user = self.users_online[index]
        user_id = self.selected_user['id']

        # If the user selects themselves, disable all buttons
        if user_id == self.client_id:
            self.block_button.config(state=tk.DISABLED)
            self.unblock_button.config(state=tk.DISABLED)
            self.report_button.config(state=tk.DISABLED)

        # If the user is already blocked, enable the 'Unblock' button
        elif self.is_user_blocked(user_id):
            self.block_button.config(state=tk.DISABLED)
            self.unblock_button.config(state=tk.NORMAL)
            self.report_button.config(state=tk.NORMAL)
        # If the user is NOT blocked, enable the 'Block' button
        else:
            self.block_button.config(state=tk.NORMAL)
            self.unblock_button.config(state=tk.DISABLED)
            self.report_button.config(state=tk.NORMAL)

    def on_address_change(self, *args):
        host = self.host_var.get().strip()
        port = self.port_entry.get().strip()

        if not host or not port:
            self.join_button.config(state=tk.DISABLED)
        else:
            self.join_button.config(state=tk.NORMAL)

    def on_message_typed(self, *args):
        content = self.message_var.get().strip()
        if not content:
            self.send_button.config(state=tk.DISABLED)
        else:
            self.send_button.config(state=tk.NORMAL)

    def block_user(self):
        # No one has been selected to block
        if not self.selected_user:
            return
        
        user_info = self.selected_user
        user_id = user_info.get('id')
        user_nick = user_info.get('nick')
        
        # Could not find user of that ID. You can't block yourself (duh)
        if not user_id or not user_nick or user_id == self.client_id:
            self.display_message('Unable to block this user.')
            return
        
        # This should never happen, but I'll leave this safety check in anyways
        if self.is_user_blocked(user_id):
            self.display_message(f'{user_nick} is already blocked.')
            return
        
        self.display_message(f'Blocked {user_nick}. Messages from this user will be suppressed.')
        self.blocked_users.append(user_id)
        write_file('blocked_users.json', self.blocked_users)

        self.block_button.config(state=tk.DISABLED)
        self.unblock_button.config(state=tk.NORMAL)

        
    def unblock_user(self):
        # No one has been selected to unblock
        if not self.selected_user:
            return
        
        user_info = self.selected_user
        user_id = user_info.get('id')
        user_nick = user_info.get('nick')
        
        # Could not find user of that ID. You can't unblock yourself (let alone block yourself in the first place)
        if not user_id or not user_nick or user_id == self.client_id:
            self.display_message('Unable to block this user.')
            return
        
        # This should never happen, but I'll leave this safety check in anyways
        if not self.is_user_blocked(user_id):
            self.display_message(f'{user_nick} is not blocked.')
            return
        
        self.display_message(f'Unblocked {user_nick}. Messages from this user will be visible again.')
        self.blocked_users.remove(user_id)
        write_file('blocked_users.json', self.blocked_users)
        
        self.block_button.config(state=tk.NORMAL)
        self.unblock_button.config(state=tk.DISABLED)

    # Sends the server a user report
    def report_user(self):
        pass

    # Checks if we blocked a user with the specified ID
    def is_user_blocked(self, user_id):
        return user_id in self.blocked_users

    def update_user_list(self, users=[]):
        self.users_online = users
        self.user_listbox.delete(0, tk.END)
        for user in users:
            nickname = user['nick']
            # If this is your name, make it obvious to the user
            if user['id'] == self.client_id:
                nickname += ' (You)'
            # self.display_message(f'User: {user['id']} - Me: {self.client_id}')
            self.user_listbox.insert(tk.END, nickname)
        
    # Listens for messages from the server and updates the chat text box
    def receive_messages(self):
        while self.client_running:
            try:
                packet = decode_packet(self.client.recv(1024))  # Parse the incoming JSON data
                packet_type = packet['type']

                # A user joined or left the chat room
                if packet_type in ['user_joined', 'user_leave']:
                    # Update the user list box according to who is currently online
                    self.update_user_list(packet['users'])

                    # Print a message saying '[user] has joined the chat.'
                    user_nick = packet['user']
                    if packet_type == 'user_joined':
                        self.display_message(f'{user_nick} joined the chat.')
                    else:
                        self.display_message(f'{user_nick} left the chat.')

                # A user sent a message
                elif packet_type == 'user_message':
                    # Print the received message to the user's chat window
                    sender = packet['sender']

                    # Ignore messages from blocked users
                    if self.is_user_blocked(sender['id']):
                        continue
                    
                    content = packet['content']
                    self.display_message(f'({sender['nick']}) {content}')
                
                # The server sent a message
                elif packet_type == 'server_message':
                    # Print the received message to the user's chat window
                    content = packet['content']
                    self.display_message(f'[SERVER] {content}')
                # The server is shutting down
                elif packet_type == 'server_closed':
                    # Disconnect from the server now that it's closing
                    self.stop_client(reason='Server closed.')
                    break
                # You were kicked or banned
                elif packet_type in ['user_kicked', 'user_banned']:
                    # You were kicked by an operator
                    reason = packet['reason']
                    punishment = 'kicked' if packet_type == 'user_kicked' else 'banned'
                    self.stop_client()
                    messagebox.showwarning(punishment.title(), message=f'You have been {punishment} from this server.\nReason: {reason}')
                    break
                # The server sent an error/warning message
                elif packet_type in ['error', 'warning']:
                    self.display_message(f'{packet_type.title()}: {packet['message']}')
                # Other cases
                else:
                    # This should never happen but I'm including a safety check just incase I do an oopsy
                    self.display_message(f'[SERVER] {packet}')
            
            except ConnectionResetError:
                self.stop_client(reason='Server closed.')
                break
            except ConnectionAbortedError:
                self.stop_client()
                break
            except Exception as e:
                self.stop_client(reason=str(e))
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
        message = self.message_entry.get().strip()
        if message:
            self.send_packet(encode_packet({'type': 'user_message', 'sender': {'nick': self.nickname, 'id': self.client_id}, 'content': message}))
            self.message_entry.delete(0, tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()
