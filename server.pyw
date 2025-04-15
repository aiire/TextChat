from datetime import datetime
import socket
import threading 
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

    @property
    def id(self):
        return generate_id(self.nickname, self.address[0])

class UserInfoDialog(tk.Toplevel):
    def __init__(self, master: tk.Tk, user_info: dict, kick_callback, ban_callback):
        super().__init__(master)
        self.title("User Info")

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

        self.resizable(False, False)
        self.grab_set()

        self.action_callback = action_callback

        main_frame = tk.Frame(self)
        main_frame.pack(padx=15, pady=15)

        label = tk.Label(main_frame, text="Reason for action:", anchor="w", width=35)
        label.pack(fill="x", pady=(0, 8))

        self.reason_entry = ttk.Entry(main_frame)
        self.reason_entry.pack(fill="x", pady=(0, 10))
        self.reason_entry.bind("<Return>", self.execute_action)
        self.reason_entry.focus()

        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(pady=5)

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.cancel)
        cancel_btn.pack(side=tk.LEFT, padx=(0, 10))  

        confirm_btn = ttk.Button(btn_frame, text="Confirm", command=self.execute_action)
        confirm_btn.pack(side=tk.LEFT, padx=(0, 10))  

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

        self.resizable(False, False)
        self.grab_set()  

        user_id = ban_info["id"]
        nickname = ban_info["nick"]
        date = ban_info["date"]
        reason = ban_info["reason"]

        self.unban_callback = unban_callback  

        main_frame = tk.Frame(self)
        main_frame.pack(padx=5, pady=5)

        info_text = f"User: {nickname} ({user_id})\nStatus: Permanently Banned\nDate: {date}\nReason: {reason}"
        tk.Label(main_frame, text=info_text, padx=10, pady=10, justify=tk.LEFT).pack()

        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Unban", command=self.unban_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=self.destroy).pack(side=tk.LEFT, padx=5)

    def unban_user(self):
        self.unban_callback()
        self.destroy()  

class ChatServer:
    def __init__(self, master: tk.Tk):
        self.master = master 
        self.master.title("Chat Room (Server)")  
        self.setup_gui()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_running = False

        self.users: list[User] = []
        bans = read_file("bans.json")
        self.bans: list[dict] = bans.get("bans", []) 

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

        self.host_frame = tk.Frame(left_frame)
        self.host_frame.pack(anchor="w", pady=(0, 10))
        self.host_label = tk.Label(self.host_frame, text="Host")
        self.host_label.pack(side=tk.LEFT)
        self.host_var = tk.StringVar(master, value=DEFAULT_HOST)
        self.host_entry = tk.Entry(self.host_frame, textvariable=self.host_var, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 0))  

        port_frame = tk.Frame(left_frame)
        port_frame.pack(anchor="w", pady=(0, 10))
        self.port_label = tk.Label(port_frame, text="Port")
        self.port_label.pack(side=tk.LEFT)
        self.port_var = tk.IntVar(master, value=DEFAULT_PORT)
        self.port_entry = tk.Entry(port_frame, textvariable=self.port_var, width=20)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 0))

        button_frame = tk.Frame(left_frame)
        button_frame.pack(anchor="w", pady=(0, 10))  

        self.start_button = ttk.Button(button_frame, text="Start Server", command=self.start_server)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))  

        self.stop_button = ttk.Button(button_frame, text="Stop Server", command=self.stop_server)
        self.stop_button.pack(side=tk.LEFT)  
        self.stop_button.config(state=tk.DISABLED)

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
        self.user_listbox.bind("<Return>", self.view_user)

        self.selected_user = None

        self.view_user_button = ttk.Button(left_frame, text="View", command=self.view_user)
        self.view_user_button.pack(side=tk.LEFT)
        self.view_user_button.config(state=tk.DISABLED)

        self.chat_area = scrolledtext.ScrolledText(center_frame, wrap=tk.WORD, state=tk.DISABLED, width=60, height=20)
        self.chat_area.pack(fill=tk.BOTH, padx=(5, 0), pady=(0, 10), expand=True)

        message_frame = tk.Frame(center_frame)
        message_frame.pack(fill=tk.BOTH, padx=(5, 0), pady=(0, 10))
        self.message_var = tk.StringVar(master)  
        self.message_var.trace_add("write", self.on_message_typed)
        self.message_entry = tk.Entry(message_frame, textvariable=self.message_var, width=60)
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_entry.config(state=tk.DISABLED)
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.send_button.config(state=tk.DISABLED)

        ban_frame = tk.Frame(right_frame)
        ban_frame.pack(anchor="w", pady=(0, 10))

        ban_list_label = tk.Label(ban_frame, text="Banned Users")
        ban_list_label.pack(anchor="w", pady=(0, 5))

        self.ban_listbox = tk.Listbox(ban_frame, width=25, height=12)
        self.ban_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

        scrollbar = tk.Scrollbar(ban_frame, orient=tk.VERTICAL, command=self.ban_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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

                initial_message = decode_packet(client.recv(1024))

                if not initial_message:
                    continue

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

                    client.sendall(encode_packet({"type": "connection_ack", "status": "success", "your_id": user_id}))

                else:
                    continue

                user = self.add_user(client, nick, address)

                thread = threading.Thread(target=self.handle_client, args=(user,))
                thread.start()
            except socket.timeout as e:
                self.display_message("Timed out.")
                continue  
            except OSError as e:

                break

    def user_table(self):
        return [{"nick": user.nickname, "id": user.id} for user in self.users]

    def add_user(self, client: socket.socket, nickname: str, address: tuple[str, int]):
        user = User(nickname, client, address)
        self.users.append(user)
        self.user_listbox.insert(tk.END, user.nickname)

        self.display_message(f"{nickname} joined the chat.")

        self.broadcast(encode_packet({"type": "user_joined", "user": nickname, "users": self.user_table()}))
        return user

    def remove_user(self, user: User):
        if user not in self.users:
            return

        self.users.remove(user)
        user.client.close()

        self.display_message(f"{user.nickname} left the chat.")

        self.broadcast(encode_packet({"type": "user_leave", "user": user.nickname, "users": self.user_table()}))

        try:
            user_index = self.user_listbox.get(0, tk.END).index(user.nickname)  
            self.user_listbox.delete(user_index)  
        except ValueError:
            pass  

    def on_user_select(self, event=None):
        selection = self.user_listbox.curselection()

        if not selection:
            self.view_user_button.config(state=tk.DISABLED)
            self.selected_user = None
            return

        index = selection[0]
        self.selected_user = self.users[int(index)]

        self.view_user_button.config(state=tk.NORMAL)

    def on_ban_select(self, event=None):
        selection = self.ban_listbox.curselection()

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
            ban_index = self.ban_listbox.get(0, tk.END).index(nick)  
            self.ban_listbox.delete(ban_index)  
        except:
            pass

        self.selected_ban = None
        self.view_ban_button.config(state=tk.DISABLED)

    def view_ban(self, event=None):
        if not self.selected_ban:
            return

        ViewBanDialog(self.master, self.selected_ban, self.unban_user)

    def handle_client(self, user: User):
        while True:
            try:
                packet = decode_packet(user.client.recv(1024)) 
                packet_type = packet["type"]

                if packet_type == "user_message":
                    sender = packet["sender"]["nick"]
                    content = packet["content"]
                    self.display_message(f"({sender}) {content}")

                    self.broadcast(encode_packet(packet))

                elif packet_type == "user_disconnected":
                    self.remove_user(user)
                    break

            except json.JSONDecodeError:
                error_response = {
                    "type": "error",
                    "message": "Invalid JSON format."
                }

                self.send_packet(user, encode_packet(error_response))
            except Exception as e:
                self.remove_user(user)
                break

    def send_packet(self, recipient: User, packet: bytes):
        recipient.client.sendall(packet)

    def clear_chat(self):        
        self.chat_area.config(state=tk.NORMAL) 
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def start_server(self):
        if self.server_running:
            return

        if not self.server:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            host = self.host_var.get()
            port = self.port_var.get()

            self.server.bind((host, port))
            self.server.listen()

            self.clear_chat()
            self.display_message(f"Listening for incoming connections on {host}:{port}")

            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            self.message_entry.config(state=tk.NORMAL)

            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)

            self.server_running = True

            listen_thread = threading.Thread(target=self.accept_connections)
            listen_thread.daemon = True
            listen_thread.start()

        except socket.gaierror:

            messagebox.showerror("Hostname Error", "Invalid host name. Please enter a valid host.")
        except socket.error as e:

            if e.errno == errno.EADDRINUSE:
                messagebox.showerror("Port Error", "The port is already in use. Please choose another port.")
            else:
                messagebox.showerror("Socket Error", f"Failed to start server:\n{e}")
        except Exception as e:

            messagebox.showerror("Unexpected Error", f"An unexpected error occurred:\n{e}")
        finally:
            if not self.server_running:
                self.server = None

    def stop_server(self):
        if not self.server_running:
            return

        self.broadcast(encode_packet({"type": "server_closed"}))

        for user in self.users:
            user.client.close()

        self.users.clear()

        self.server_running = False
        self.server.close()
        self.server = None

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        self.send_button.config(state=tk.DISABLED)
        self.message_entry.config(state=tk.DISABLED)

        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)

        self.view_user_button.config(state=tk.DISABLED)

        self.clear_chat()

        self.user_listbox.delete(0, tk.END)

    def broadcast(self, packet: bytes):
        if not self.server_running:
            return

        for user in self.users:
            self.send_packet(user, packet)

    def display_message(self, message: str):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + "\n") 
        self.chat_area.see(tk.END)  
        self.chat_area.config(state=tk.DISABLED)  

    def send_message(self, event=None):
        message = self.message_var.get().strip() 
        if not message:
            return

        self.display_message(f"[SERVER] {message}")
        self.broadcast(encode_packet({"type": "server_message", "content": message})) 

        self.message_entry.delete(0, tk.END) 

if __name__ == "__main__":
    root = tk.Tk()
    server = ChatServer(root)
    root.mainloop()