import tkinter as tk
from tkinter import ttk
import random
import string
import pyperclip

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")

        self.length_label = ttk.Label(root, text="Password Length:")
        self.length_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

        self.length_var = tk.IntVar()
        self.length_entry = ttk.Entry(root, textvariable=self.length_var)
        self.length_entry.grid(row=0, column=1, padx=10, pady=10)

        self.uppercase_var = tk.BooleanVar()
        self.uppercase_checkbox = ttk.Checkbutton(root, text="Uppercase", variable=self.uppercase_var)
        self.uppercase_checkbox.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.lowercase_var = tk.BooleanVar()
        self.lowercase_checkbox = ttk.Checkbutton(root, text="Lowercase", variable=self.lowercase_var)
        self.lowercase_checkbox.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

        self.digits_var = tk.BooleanVar()
        self.digits_checkbox = ttk.Checkbutton(root, text="Digits", variable=self.digits_var)
        self.digits_checkbox.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

        self.special_var = tk.BooleanVar()
        self.special_checkbox = ttk.Checkbutton(root, text="Special Characters", variable=self.special_var)
        self.special_checkbox.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)

        self.generate_button = ttk.Button(root, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=5, column=0, columnspan=2, pady=10)

        self.password_label = ttk.Label(root, text="Generated Password:")
        self.password_label.grid(row=6, column=0, padx=10, pady=10, sticky=tk.W)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(root, textvariable=self.password_var, state="readonly")
        self.password_entry.grid(row=6, column=1, padx=10, pady=10, sticky=tk.W)

        self.copy_button = ttk.Button(root, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=7, column=0, columnspan=2, pady=10)

    def generate_password(self):
        length = self.length_var.get()

        if length <= 0:
            return

        characters = ""

        if self.uppercase_var.get():
            characters += string.ascii_uppercase
        if self.lowercase_var.get():
            characters += string.ascii_lowercase
        if self.digits_var.get():
            characters += string.digits
        if self.special_var.get():
            characters += string.punctuation

        if not characters:
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            print("Password copied to clipboard")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()