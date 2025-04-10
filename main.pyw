import tkinter as tk
from tkinter import ttk
import subprocess
import sys

def start_client_program():
    subprocess.Popen([sys.executable, 'client.pyw'])

def start_server_program():
    subprocess.Popen([sys.executable, 'server.pyw'])

def main():
    root = tk.Tk()
    root.title('Chat Room Launcher')
    root.geometry('320x180')
    root.resizable(False, False)

    main_frame = ttk.Frame(root, padding=20)
    main_frame.pack(expand=True, fill=tk.BOTH)

    title_label = ttk.Label(main_frame, text='Select an option')
    title_label.pack(pady=(0, 15))

    btn_client = ttk.Button(main_frame, text='Launch Client', command=start_client_program)
    btn_client.pack(fill=tk.X, pady=5)

    btn_server = ttk.Button(main_frame, text='Launch Server', command=start_server_program)
    btn_server.pack(fill=tk.X, pady=5)

    root.mainloop()

if __name__ == '__main__':
    main()
