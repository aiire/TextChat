from datetime import datetime
import socket
import threading # Multi-threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, ttk
import json
import errno
from dataclasses import dataclass, field
import time

from common import *

@dataclass
class User:
    nickname: str
    client: socket.socket
    address: tuple[str, int]
    message_timestamps: list[float] = field(default_factory=list)

    # A users unique identifier determined by their nickname and IP address
    @property
    def id(self):
        # Combine the hashes of the nickname and the IP
        return generate_id(self.nickname, self.address[0])

class UserInfoDialog(tk.Toplevel):
    def __init__(self, master: tk.Tk, user_info: dict, kick_callback, ban_callback):
        super().__init__(master)
        self.title("User Info")
        # self.geometry("300x160")
        self.resizable(False, False)
        self.grab_set()

        self.user_info = user_info
        self.kick_callback = kick_callback
        self.ban_callback = ban_callback

        user_id = user_info["id"]
        nickname = user_info["nick"]

        main_frame = tk.Frame(self)
        main_frame.pack(padx=5, pady=5)

        info_text = f"User: {nickname}\nID: {user_id}"
        tk.Label(main_frame, text=info_text, padx=10, pady=10, justify=tk.LEFT).pack()

        # Button frame
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Kick", command=self.open_kick_dialog,).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Ban", command=self.open_ban_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=self.destroy).pack(side=tk.LEFT, padx=5)

    def open_kick_dialog(self):
        AdminActionDialog(self, self.kick_callback)

    def open_ban_dialog(self):
        AdminActionDialog(self, self.ban_callback)

class AdminActionDialog(tk.Toplevel):
    def __init__(self, master: tk.Tk, action_callback):
        super().__init__(master)
        self.title("Administrative Action")
        # self.geometry("400x150")
        self.resizable(False, False)
        self.grab_set()
        # self.configure(padx=20, pady=20)

        self.action_callback = action_callback

        main_frame = tk.Frame(self)
        main_frame.pack(padx=15, pady=15)

        # Reason label
        label = tk.Label(main_frame, text="Reason for action:", anchor="w", width=35)
        label.pack(fill="x", pady=(0, 8))

        # Reason entry field
        self.reason_entry = ttk.Entry(main_frame)
        self.reason_entry.pack(fill="x", pady=(0, 10))
        self.reason_entry.bind("<Return>", self.execute_action)
        self.reason_entry.focus()

        # Button frame
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(pady=5)

        # Buttons
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.cancel)
        cancel_btn.pack(side=tk.LEFT, padx=(0, 10))  # Left alignment with padding

        confirm_btn = ttk.Button(btn_frame, text="Confirm", command=self.execute_action)
        confirm_btn.pack(side=tk.LEFT, padx=(0, 10))  # Left alignment with padding

    def cancel(self):
        self.destroy()
        self.master.destroy()

    def execute_action(self, event=None):
        reason = self.reason_entry.get().strip()
        if not reason:
            reason = "Banned by an admin."
        self.action_callback(reason)
        self.cancel()

class ViewBanDialog(tk.Toplevel):
    def __init__(self, master: tk.Tk, ban_info: dict, unban_callback):
        super().__init__(master)
        self.title("Ban Info")
        # self.geometry("280x200")
        self.resizable(False, False)
        self.grab_set()  # Make the dialog modal

        user_id = ban_info["id"]
        nickname = ban_info["nick"]
        date = ban_info["date"]
        reason = ban_info["reason"]

        self.unban_callback = unban_callback  # Store the external callback

        main_frame = tk.Frame(self)
        main_frame.pack(padx=5, pady=5)

        # Ban information
        info_text = f"User: {nickname} ({user_id})\nStatus: Permanently Banned\nDate: {date}\nReason: {reason}"
        tk.Label(main_frame, text=info_text, padx=10, pady=10, justify=tk.LEFT).pack()

        # Buttons
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Unban", command=self.unban_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=self.destroy).pack(side=tk.LEFT, padx=5)

    def unban_user(self):
        # Call the external unban function
        self.unban_callback()
        self.destroy()  # Close the dialog
        
class ChatServer:
    def __init__(self, master: tk.Tk):
        self.master = master # Store the root widget
        self.master.title("Chat Room (Server)")  # Set the title of the GUI window to "Chat Server"
        self.setup_gui()

        # Server socket and client sockets
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_running = False
        
        # The list storing the connected users
        self.users: list[User] = []
        bans = read_file("bans.json")
        self.bans: list[dict] = bans.get("bans", []) # List of banned users

        for ban in self.bans:
            self.ban_listbox.insert(tk.END, ban["nick"])
    
    def setup_gui(self):
        master = self.master

        main_frame = tk.Frame(master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, anchor="n")

        center_frame = tk.Frame(main_frame)
        center_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.LEFT, anchor="n", padx=5)

        # Allow the user to specify the chat room hostname
        self.host_frame = tk.Frame(left_frame)
        self.host_frame.pack(anchor="w", pady=(0, 10))
        self.host_label = tk.Label(self.host_frame, text="Host")
        self.host_label.pack(side=tk.LEFT)
        self.host_var = tk.StringVar(master, value=DEFAULT_HOST)
        self.host_entry = tk.Entry(self.host_frame, textvariable=self.host_var, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 0))  # Spacing between label and entry

        # Allow the user to enter the port 
        port_frame = tk.Frame(left_frame)
        port_frame.pack(anchor="w", pady=(0, 10))
        self.port_label = tk.Label(port_frame, text="Port")
        self.port_label.pack(side=tk.LEFT)
        self.port_var = tk.IntVar(master, value=DEFAULT_PORT)
        self.port_entry = tk.Entry(port_frame, textvariable=self.port_var, width=20)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Create a frame for the buttons to keep them on the same line
        button_frame = tk.Frame(left_frame)
        button_frame.pack(anchor="w", pady=(0, 10))  # Packs the frame in left_frame

        # Add the Start Server button inside button_frame
        self.start_button = ttk.Button(button_frame, text="Start Server", command=self.start_server)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))  # Left alignment with padding

        # Add the Stop Server button inside button_frame
        self.stop_button = ttk.Button(button_frame, text="Stop Server", command=self.stop_server)
        self.stop_button.pack(side=tk.LEFT)  # Left alignment next to start button
        self.stop_button.config(state=tk.DISABLED)

        # Listbox for connected users
        # Create a frame for the listbox and scrollbar together
        list_frame = tk.Frame(left_frame)
        list_frame.pack(anchor="w", pady=(0, 10))

        # Label remains above the list_frame
        user_list_label = tk.Label(list_frame, text="Users Online")
        user_list_label.pack(anchor="w", pady=(0, 5))

        # Create the listbox inside the frame
        self.user_listbox = tk.Listbox(list_frame, width=25, height=12)
        self.user_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

        # Create and attach the scrollbar to the listbox within the same frame
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.user_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Connect the listbox to the scrollbar
        self.user_listbox.config(yscrollcommand=scrollbar.set)
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_select)
        self.user_listbox.bind("<Return>", self.view_user)

        # Store the selected user, if any
        self.selected_user = None

        # Added functionality for kicking disruptive users
        self.view_user_button = ttk.Button(left_frame, text="View", command=self.view_user)
        self.view_user_button.pack(side=tk.LEFT)
        self.view_user_button.config(state=tk.DISABLED)

        # And add a button to stop the server
        self.chat_area = scrolledtext.ScrolledText(center_frame, wrap=tk.WORD, state=tk.DISABLED, width=60, height=20)
        self.chat_area.pack(fill=tk.BOTH, padx=(5, 0), pady=(0, 10), expand=True)

        # Frame to hold the message entry and send button
        message_frame = tk.Frame(center_frame)
        message_frame.pack(fill=tk.BOTH, padx=(5, 0), pady=(0, 10))
        self.message_var = tk.StringVar(master)  # Changed from IntVar to StringVar for text input
        self.message_var.trace_add("write", self.on_message_typed)
        self.message_entry = tk.Entry(message_frame, textvariable=self.message_var, width=60)
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_entry.config(state=tk.DISABLED)
        self.message_entry.bind("<Return>", self.send_message)

        # Send Button
        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.send_button.config(state=tk.DISABLED)
        
        # Listbox for banned users
        # Create a frame for the listbox and scrollbar together
        ban_frame = tk.Frame(right_frame)
        ban_frame.pack(anchor="w", pady=(0, 10))

        # Label remains above the list_frame
        ban_list_label = tk.Label(ban_frame, text="Banned Users")
        ban_list_label.pack(anchor="w", pady=(0, 5))

        # Create the listbox inside the frame
        self.ban_listbox = tk.Listbox(ban_frame, width=25, height=12)
        self.ban_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

        # Create and attach the scrollbar to the listbox within the same frame
        scrollbar = tk.Scrollbar(ban_frame, orient=tk.VERTICAL, command=self.ban_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Connect the listbox to the scrollbar
        self.ban_listbox.config(yscrollcommand=scrollbar.set)
        self.ban_listbox.bind("<<ListboxSelect>>", self.on_ban_select)
        self.ban_listbox.bind("<Return>", self.view_ban)
        
        self.view_ban_button = ttk.Button(right_frame, text="View", command=self.view_ban)
        self.view_ban_button.pack(side=tk.LEFT)
        self.view_ban_button.config(state=tk.DISABLED)
            
    def get_ban_info(self, user_id) -> dict | None:
        return next((ban for ban in self.bans if ban["id"] == user_id), None)

    def is_user_banned(self, user_id):
        return any(ban["id"] == user_id for ban in self.bans)
    
    def is_nick_taken(self, nickname):
        duplicate_nicks = [user.nickname for user in self.users if user.nickname == nickname]
        return len(duplicate_nicks) > 0

    def accept_connections(self):
        while self.server_running:
            try:
                client, address = self.server.accept()
                # self.display_message(f"Connected to {address}")
                
                # The client will send a packet saying the user is requesting to join the chat room
                initial_message = decode_packet(client.recv(1024))
                
                # The incoming data could not be parsed
                if not initial_message:
                    continue

                # If the client is actively requesting to connect...
                if initial_message["type"] == "user_connected":
                    nick = initial_message["nick"]
                    user_id = generate_id(nick, address[0])
                    error_response = {"type": "connection_error", "status": "failed"}
                    if self.is_user_banned(user_id):
                        ban_info = self.get_ban_info(user_id)
                        if ban_info:
                            error_response["status"] = "banned"
                            error_response["reason"] = ban_info.get("reason", "Banned by an admin.")
                            client.sendall(encode_packet(error_response))
                        continue
                    elif self.is_nick_taken(nick):
                        error_response["status"] = "nick_taken"
                        error_response["reason"] = f"The nick \"{nick}\" is already in use."
                        client.sendall(encode_packet(error_response))
                        continue
                    
                    # Send an acknowledgement to the user to let them know connection was successful
                    client.sendall(encode_packet({"type": "connection_ack", "status": "success", "your_id": user_id}))

                # Most likely the client sent an unexpected packet
                else:
                    continue
                
                # Add the user to the chat room
                user = self.add_user(client, nick, address)

                # Start a thread to handle the new client
                thread = threading.Thread(target=self.handle_client, args=(user,))
                thread.start()
            except socket.timeout as e:
                self.display_message("Timed out.")
                continue  # Timeout occurred, check the loop condition again
            except OSError as e:
                # Socket was likely closed, exit the loop
                break
    
    def user_table(self):
        return [{"nick": user.nickname, "id": user.id} for user in self.users]
    
    # Add a user to the chat room
    def add_user(self, client: socket.socket, nickname: str, address: tuple[str, int]):
        user = User(nickname, client, address)
        self.users.append(user)
        self.user_listbox.insert(tk.END, user.nickname)

        # Display a message that the user has joined
        self.display_message(f"{nickname} joined the chat.")

        # Notify others that a new user has joined
        self.broadcast(encode_packet({"type": "user_joined", "user": nickname, "users": self.user_table()}))
        return user

    # Remove a user from the chat room
    def remove_user(self, user: User):
        # I have no idea who you are
        if user not in self.users:
            return
        
        self.users.remove(user)
        user.client.close()

        # Display a message that the user left
        self.display_message(f"{user.nickname} left the chat.")
        
        # Notify others that a user has left
        self.broadcast(encode_packet({"type": "user_leave", "user": user.nickname, "users": self.user_table()}))

        # Remove their name from the user list
        try:
            user_index = self.user_listbox.get(0, tk.END).index(user.nickname)  # Find the nickname index
            self.user_listbox.delete(user_index)  # Remove from listbox
        except ValueError:
            pass  # for wtv reason this user"s nickname is not listed

    
    # Executes when the host selects a user in the user list 
    def on_user_select(self, event=None):
        selection = self.user_listbox.curselection()

        # If there is no user selected, disable moderation buttons
        if not selection:
            self.view_user_button.config(state=tk.DISABLED)
            self.selected_user = None
            return

        index = selection[0]
        self.selected_user = self.users[int(index)]
        
        self.view_user_button.config(state=tk.NORMAL)

    
    # Executes when the host selects a ban in the ban list 
    def on_ban_select(self, event=None):
        selection = self.ban_listbox.curselection()

        # If there is no user ban selected, disable the "View Ban" button
        if not selection:
            self.view_ban_button.config(state=tk.DISABLED)
            self.selected_ban = None
            return

        index = selection[0]
        self.selected_ban = self.bans[int(index)]
        self.view_ban_button.config(state=tk.NORMAL)

    def on_message_typed(self, *args):
        content = self.message_var.get().strip()
        if not content:
            self.send_button.config(state=tk.DISABLED)
        else:
            self.send_button.config(state=tk.NORMAL)
    
    def view_user(self, event=None):
        if not self.selected_user:
            return
        user_id = self.selected_user.id
        nick = self.selected_user.nickname
        UserInfoDialog(self.master, {"id": user_id, "nick": nick}, self.kick_user, self.ban_user)

    def kick_user(self, reason):
        if not self.selected_user:
            return
        
        target_user = self.selected_user
        
        self.display_message(f"Kicked {target_user.nickname}.")
        self.send_packet(target_user, encode_packet({"type": "user_kicked", "reason": reason}))
        self.remove_user(target_user)

        self.selected_user = None
        self.view_user_button.config(state=tk.DISABLED)

    def ban_user(self, reason):
        if not self.selected_user:
            return
        
        target_user = self.selected_user
            
        self.display_message(f"Banned {target_user.nickname}.")

        self.send_packet(target_user, encode_packet({
            "type": "user_banned", 
            "reason": reason
        }))
        
        self.ban_listbox.insert(tk.END, target_user.nickname)
        self.remove_user(target_user)
        self.bans.append({
            "id": target_user.id, 
            "nick": target_user.nickname, 
            "date": datetime.today().strftime("%Y-%m-%d"), 
            "reason": reason
        })
        write_file("bans.json", {"bans": self.bans})

        self.selected_user = None
        self.view_user_button.config(state=tk.DISABLED)

    def unban_user(self):
        if not self.selected_ban:
            return
        
        nick = self.selected_ban["nick"]
        self.display_message(f"Unbanned {nick}.")
        self.bans.remove(self.selected_ban)
        write_file("bans.json", {"bans": self.bans})

        try:
            ban_index = self.ban_listbox.get(0, tk.END).index(nick)  # Find the nickname index
            self.ban_listbox.delete(ban_index)  # Remove from listbox
        except:
            pass

        self.selected_ban = None
        self.view_ban_button.config(state=tk.DISABLED)
    
    def view_ban(self, event=None):
        if not self.selected_ban:
            return
        
        ViewBanDialog(self.master, self.selected_ban, self.unban_user)

    # Handles incoming messages from a client. Runs on its own work thread for each client
    def handle_client(self, user: User):
        while True:
            try:
                # Receive message from the client and parse it as JSON data
                packet = decode_packet(user.client.recv(1024)) 
                packet_type = packet["type"]

                print(f"Received: {packet}")

                # This user sent a message
                if packet_type == "user_message":
                    # Print the received message to the server chat window
                    sender = packet["sender"]["nick"]
                    content = packet["content"]
                    self.display_message(f"({sender}) {content}")

                    # Echo the received message to other clients
                    self.broadcast(encode_packet(packet))
                
                # User wants to disconnect from the server
                elif packet_type == "user_disconnected":
                    self.remove_user(user)
                    break

            except json.JSONDecodeError:
                # Couldn"t parse packet JSON data
                error_response = {
                    "type": "error",
                    "message": "Invalid JSON format."
                }
                # This should pretty much never happen but I"ll include it anyway
                self.send_packet(user, encode_packet(error_response))
            except Exception as e:
                self.remove_user(user)
                break

    def send_packet(self, recipient: User, packet: bytes):
        # self.display_message(packet.decode())
        recipient.client.sendall(packet)

    def clear_chat(self):        
        self.chat_area.config(state=tk.NORMAL) # Enable editing first
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.config(state=tk.DISABLED)

    # Name speaks for itself
    def start_server(self):
        # Don"t try and start the server if it is already running
        if self.server_running:
            return
        
        # Create a new socket instance every time you start the server
        if not self.server:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # Retrieve host name and port from their respective text entries
            host = self.host_var.get()
            port = self.port_var.get()
            
            # Open the server socket and listen for incoming connections
            self.server.bind((host, port))
            self.server.listen()
            # self.server.settimeout(1.0)  # Set a 1-second timeout

            # Clear all messages printed in chat (if any)
            self.clear_chat()
            self.display_message(f"Listening for incoming connections on {host}:{port}")

            # Enable "Stop Server" button and disable "Start Server" button
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            # Enable "Send" button and the message entry
            # self.send_button.config(state=tk.NORMAL)
            self.message_entry.config(state=tk.NORMAL)

            # Disable "Host" and "Port" entries
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            
            # Clear all messages printed in chat (if any)
            self.server_running = True

            # Start a thread to continuously listen for connections
            listen_thread = threading.Thread(target=self.accept_connections)
            listen_thread.daemon = True
            listen_thread.start()

        except socket.gaierror:
            # Raised for address-related errors, typically an invalid host name
            messagebox.showerror("Hostname Error", "Invalid host name. Please enter a valid host.")
        except socket.error as e:
            # This address is in use by another program
            if e.errno == errno.EADDRINUSE:
                messagebox.showerror("Port Error", "The port is already in use. Please choose another port.")
            else:
                messagebox.showerror("Socket Error", f"Failed to start server:\n{e}")
        except Exception as e:
            # If all else fails...
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred:\n{e}")
        finally:
            if not self.server_running:
                self.server = None

    # Close the server socket and all connected client sockets
    def stop_server(self):
        if not self.server_running:
            return
        
        # Notify users that the server is closing
        self.broadcast(encode_packet({"type": "server_closed"}))
        
        # Close all connected sockets
        for user in self.users:
            user.client.close()
        
        self.users.clear()

        # Close the server and reset variables
        self.server_running = False
        self.server.close()
        self.server = None

        # Enable "Start Server" button and disable "Stop Server" button
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        # Disable "Send" button and the message text entry
        self.send_button.config(state=tk.DISABLED)
        self.message_entry.config(state=tk.DISABLED)

        # Enable "Host" and "Port" entries
        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        
        # Disable "View" button
        self.view_user_button.config(state=tk.DISABLED)

        # Clear all messages printed in chat
        self.clear_chat()

        # Clear user list
        self.user_listbox.delete(0, tk.END)

    # Send a packet to all users
    def broadcast(self, packet: bytes):
        if not self.server_running:
            return
        
        for user in self.users:
            self.send_packet(user, packet)

    def display_message(self, message: str):
        # print(message)
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + "\n") # Insert the message at the end
        self.chat_area.see(tk.END)  # Auto-scroll to the new message
        self.chat_area.config(state=tk.DISABLED)  # Prevent user edits
        
    def send_message(self, event=None):
        message = self.message_var.get().strip() # Retrieve what the host typed in the message box
        if not message:
            return

        self.display_message(f"[SERVER] {message}") # Log the message to the chat
        self.broadcast(encode_packet({"type": "server_message", "content": message})) # Broadcast the message to every client

        self.message_entry.delete(0, tk.END) # Clear the text box 

# Ensuring the script runs only when executed directly (not imported as a module)
if __name__ == "__main__":
    root = tk.Tk()
    server = ChatServer(root)
    root.mainloop()