import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, ttk
import errno
import random
from typing import Optional
import requests

from common import *

def get_random_username(fallback=False):
    if fallback:
        fallback_nick = random.choice(["Guest", "guest", "guest_", "User", "user", "user_"])
        for _ in range(5):
            fallback_nick += f"{random.randint(0, 9)}"
        return fallback_nick
    else:
        try:
            url = "https://usernameapiv1.vercel.app/api/random-usernames"
            response = requests.get(url)
            data = response.json()
            if response.status_code == 200:
                username = data["usernames"][0]
                return username
            else:
                return get_random_username(fallback=True)
        except requests.RequestException:
            return get_random_username(fallback=True)

class ChatClient:
    def __init__(self, master: tk.Tk):
        self.master = master 
        self.master.title("Chat Room (Client)")  

        self.setup_gui()

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_running = False
        self.client_id = None
        self.nickname = None

        blocked_users = read_file("blocked_users.json")
        self.blocked_users = blocked_users.get("blocks", [])

    def setup_gui(self):
        master = self.master

        main_frame = tk.Frame(master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, anchor="n")  

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)  

        validate_number = master.register(lambda P: P.isdigit() or P == "")

        host_frame = tk.Frame(left_frame)
        host_frame.pack(anchor="w", pady=(0, 10))
        host_label = tk.Label(host_frame, text="Host")
        host_label.pack(side=tk.LEFT)
        self.host_var = tk.StringVar(master, value=DEFAULT_HOST)
        self.host_var.trace_add("write", self.on_address_change)  
        self.host_entry = tk.Entry(host_frame, textvariable=self.host_var, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 0))  

        port_frame = tk.Frame(left_frame)
        port_frame.pack(anchor="w", pady=(0, 10))
        port_label = tk.Label(port_frame, text="Port")
        port_label.pack(side=tk.LEFT)
        self.port_var = tk.IntVar(master, value=DEFAULT_PORT)
        self.port_var.trace_add("write", self.on_address_change)  
        self.port_entry = tk.Entry(port_frame, validate="key", validatecommand=(validate_number, "%P"), textvariable=self.port_var, width=20)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 0))

        button_frame = tk.Frame(left_frame)
        button_frame.pack(anchor="w", pady=(0, 10))  

        self.join_button = ttk.Button(button_frame, text="Join", command=self.start_client)
        self.join_button.pack(side=tk.LEFT, padx=(0, 10))  

        self.leave_button = ttk.Button(button_frame, text="Leave", command=self.stop_client)
        self.leave_button.pack(side=tk.LEFT)  
        self.leave_button.config(state=tk.DISABLED)

        list_frame = tk.Frame(left_frame)
        list_frame.pack(anchor="w", pady=(0, 10))

        user_list_label = tk.Label(list_frame, text="Users Online")
        user_list_label.pack(anchor="w", pady=(0, 5))

        self.user_listbox = tk.Listbox(list_frame, width=25, height=12)
        self.user_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.user_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.user_listbox.config(yscrollcommand=scrollbar.set)
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_select)

        self.block_button = ttk.Button(left_frame, text="Block", command=self.block_user)
        self.block_button.pack(side=tk.LEFT, padx=(0, 10))
        self.block_button.config(state=tk.DISABLED)

        self.unblock_button = ttk.Button(left_frame, text="Unblock", command=self.unblock_user)
        self.unblock_button.pack(side=tk.LEFT, padx=(0, 10))
        self.unblock_button.config(state=tk.DISABLED)

        self.chat_area = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, state=tk.DISABLED, width=60, height=20)
        self.chat_area.pack(fill=tk.BOTH, pady=(0, 10), expand=True)

        message_frame = tk.Frame(right_frame)
        message_frame.pack(fill=tk.BOTH, pady=(0, 10))
        self.message_var = tk.StringVar(master)  
        self.message_var.trace_add("write", self.on_message_typed)
        self.message_entry = tk.Entry(message_frame, textvariable=self.message_var, width=60)
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_entry.config(state=tk.DISABLED)
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.send_button.config(state=tk.DISABLED)

    def ask_nick(self):
        while not self.nickname:
            generated_name = get_random_username()
            nickname = simpledialog.askstring(
                "Nickname",
                f"Please choose a nickname (max {MAX_NICKNAME_LENGTH} characters)",
                initialvalue=generated_name,
                parent=self.master
            )
            if nickname:
                nickname = nickname.strip()
                if len(nickname) <= MAX_NICKNAME_LENGTH:
                    self.nickname = nickname
                else:
                    messagebox.showerror("Nickname Too Long", f"Nickname must be {MAX_NICKNAME_LENGTH} characters or fewer.")

    def clear_chat(self):
        self.chat_area.config(state=tk.NORMAL) 
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def start_client(self):
        if self.client_running:
            return

        self.ask_nick()

        if not self.client:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.clear_chat()

            host = self.host_var.get()
            port = self.port_var.get()

            self.client.connect((host, port))
            self.send_packet(encode_packet({"type": "user_connected", "nick": self.nickname}))

            response = decode_packet(self.client.recv(1024))
            response_type = response.get("type")
            response_status = response.get("status")

            if response_type == "connection_ack":
                self.client_id = response.get("your_id")
                self.display_message(f"Established connection with {host}:{port}")
                self.send_packet(encode_packet({"type": "user_joined", "nick": self.nickname}))
            elif response_type == "connection_error":
                reason = response.get("reason")
                if response_status == "banned":
                    self.stop_client()
                    messagebox.showwarning("Forbidden", f"You are banned from this server.\nReason: {reason}")
                    return
                if response_status == "nick_taken":
                    self.stop_client()
                    messagebox.showwarning("Nickname Taken", reason)
                    return

                self.stop_client()
                messagebox.showwarning("Connection Error", f"Failed to connect to server: {reason}")
                return
            else:
                raise Exception(f"Received invalid packet of type \"{response_type}\".")

            self.join_button.config(state=tk.DISABLED)
            self.leave_button.config(state=tk.NORMAL)

            self.message_entry.config(state=tk.NORMAL)

            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)

            self.client_running = True

            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

        except socket.gaierror:
            messagebox.showwarning("Hostname Error", "Invalid server address. Please enter a valid host.")
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                messagebox.showwarning("Connection Error", "Failed to connect: Connection refused by the server.")
            else:
                messagebox.showwarning("Socket Error", f"Failed to connect to server:\n{e}")
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred:\n{e}")

        if not self.client_running:
            self.stop_client()

    def stop_client(self, reason=None):
        try:
            self.send_packet(encode_packet({"type": "user_disconnect", "user": self.nickname}))
        except:
            pass

        self.client_running = False
        if self.client:
            self.client.close()
            self.client = None
        self.nickname = None

        self.join_button.config(state=tk.NORMAL)
        self.leave_button.config(state=tk.DISABLED)

        self.send_button.config(state=tk.DISABLED)
        self.message_entry.config(state=tk.DISABLED)

        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)

        self.block_button.config(state=tk.DISABLED)
        self.unblock_button.config(state=tk.DISABLED)

        self.clear_chat()
        self.update_user_list() 

        if reason:
            self.display_message(f"Connection Lost: {reason}")

    def on_user_select(self, event=None):
        selection = self.user_listbox.curselection()

        if not selection:
            self.block_button.config(state=tk.DISABLED)
            self.unblock_button.config(state=tk.DISABLED)
            self.selected_user = None
            return

        index = selection[0]
        self.selected_user = self.users_online[index]
        user_id = self.selected_user["id"]

        if user_id == self.client_id:
            self.block_button.config(state=tk.DISABLED)
            self.unblock_button.config(state=tk.DISABLED)

        elif self.is_user_blocked(user_id):
            self.block_button.config(state=tk.DISABLED)
            self.unblock_button.config(state=tk.NORMAL)

        else:
            self.block_button.config(state=tk.NORMAL)
            self.unblock_button.config(state=tk.DISABLED)

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
        if not self.selected_user:
            return

        user_info = self.selected_user
        user_id = user_info.get("id")
        user_nick = user_info.get("nick")

        if not user_id or not user_nick or user_id == self.client_id:
            self.display_message("Unable to block this user.")
            return

        if self.is_user_blocked(user_id):
            self.display_message(f"{user_nick} is already blocked.")
            return

        self.display_message(f"Blocked {user_nick}. Messages from this user will be suppressed.")
        self.blocked_users.append({"id": user_id, "nick": user_nick})
        write_file("blocked_users.json", {"blocked": self.blocked_users})

        self.block_button.config(state=tk.DISABLED)
        self.unblock_button.config(state=tk.NORMAL)

    def unblock_user(self):
        if not self.selected_user:
            return

        user_info = self.selected_user
        user_id = user_info.get("id")
        user_nick = user_info.get("nick")

        if not user_id or not user_nick or user_id == self.client_id:
            self.display_message("Unable to block this user.")
            return

        if not self.is_user_blocked(user_id):
            self.display_message(f"{user_nick} is not blocked.")
            return

        self.display_message(f"Unblocked {user_nick}. Messages from this user will be visible again.")
        self.blocked_users.remove(user_info)
        write_file("blocked_users.json", {"blocked": self.blocked_users})

        self.block_button.config(state=tk.NORMAL)
        self.unblock_button.config(state=tk.DISABLED)

    def is_user_blocked(self, user_id):        
        return any(block["id"] == user_id for block in self.blocked_users)

    def update_user_list(self, users=[]):
        self.users_online = users
        self.user_listbox.delete(0, tk.END)
        for user in users:
            nickname = user["nick"]

            if user["id"] == self.client_id:
                nickname += " (You)"

            self.user_listbox.insert(tk.END, nickname)

    def receive_messages(self):
        while self.client_running:
            try:
                packet = decode_packet(self.client.recv(1024))  
                packet_type = packet["type"]

                if packet_type in ["user_joined", "user_leave"]:

                    self.update_user_list(packet["users"])

                    user_nick = packet["user"]
                    if packet_type == "user_joined":
                        self.display_message(f"{user_nick} joined the chat.")
                    else:
                        self.display_message(f"{user_nick} left the chat.")

                elif packet_type == "user_message":
                    sender = packet["sender"]

                    if self.is_user_blocked(sender["id"]):
                        continue

                    content = packet["content"]
                    self.display_message(f"({sender["nick"]}) {content}")

                elif packet_type == "server_message":

                    content = packet["content"]
                    self.display_message(f"[SERVER] {content}")
                elif packet_type == "server_closed":
                    self.stop_client(reason="Server closed.")
                    break
                elif packet_type in ["user_kicked", "user_banned"]:
                    reason = packet["reason"]
                    punishment = "kicked" if packet_type == "user_kicked" else "banned"
                    self.stop_client()
                    messagebox.showwarning(punishment.title(), message=f"You have been {punishment} from this server.\nReason: {reason}")
                    break
                elif packet_type in ["error", "warning"]:
                    self.display_message(f"{packet_type.title()}: {packet["message"]}")
                else:
                    self.display_message(f"[SERVER] {packet}")

            except ConnectionResetError:
                self.stop_client(reason="Server closed.")
                break
            except ConnectionAbortedError:
                self.stop_client()
                break
            except Exception as e:
                self.stop_client(reason=str(e))
                break

    def display_message(self, message: str):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def send_packet(self, packet: bytes):
        self.client.sendall(packet)

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if message:
            self.send_packet(encode_packet({"type": "user_message", "sender": {"nick": self.nickname, "id": self.client_id}, "content": message}))
            self.message_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()