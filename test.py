import tkinter as tk
from tkinter import messagebox
from tkinter import PhotoImage
from PIL import Image, ImageTk
import tempfile
import webbrowser
import os
import re
from zxcvbn import zxcvbn

# Create window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("600x500")
root.configure(bg='black')

# Center the window
window_width = 600
window_height = 500
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = int((screen_width / 2) - (window_width / 2))
y = int((screen_height / 2) - (window_height / 2))
root.geometry(f"{window_width}x{window_height}+{x}+{y}")

# Set icon using a PNG file
test_img = PhotoImage(file="icon.png")
test_label = tk.Label(root, image=test_img)
test_label.pack()


# Project Info Window
def project_info():
    html_content = "<html><head><title>Info</title></head><body><h1>Password Strength Checker</h1></body></html>"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode='w', encoding='utf-8') as f:
        f.write(html_content)
        webbrowser.open('file://' + os.path.realpath(f.name))

# Password Check Function
def check_password():
    password = input_text.get()

    strength_window = tk.Toplevel(root)
    strength_window.title("Password Strength")
    strength_window.geometry("600x400")
    strength_window.configure(bg='black')

    password_label = tk.Label(strength_window, text=f"Your Password: {password}", fg="red", bg="black", font=("Arial", 12, "bold"))
    password_label.pack(pady=10)

    requirement_frame = tk.Frame(strength_window, bg="white")
    requirement_frame.pack(pady=10, fill="x", padx=20)

    time_frame = tk.Frame(strength_window, bg="white")
    time_frame.pack(pady=10, fill="x", padx=20)

    suggestion_frame = tk.Frame(strength_window, bg="white")
    suggestion_frame.pack(pady=10, fill="x", padx=20)

    if len(password) >= 8 and \
       re.search(r'[A-Z]', password) and \
       re.search(r'\d', password) and \
       re.search(r'[!@#$%^&*()_+{}\[\]:;"\'<>,.?/~`]', password):
        msg = "All Password Requirements Satisfied!"
        tk.Label(requirement_frame, text=msg, bg="white", fg="green", font=("Arial", 10)).pack()
    else:
        if len(password) < 8:
            tk.Label(requirement_frame, text="Must be at least 8 characters!", bg="white", fg="red").pack()
        if not re.search(r'[A-Z]', password):
            tk.Label(requirement_frame, text="Must contain a capital letter!", bg="white", fg="red").pack()
        if not re.search(r'\d', password):
            tk.Label(requirement_frame, text="Must contain a digit!", bg="white", fg="red").pack()
        if not re.search(r'[!@#$%^&*()_+{}\[\]:;"\'<>,.?/~`]', password):
            tk.Label(requirement_frame, text="Must contain a special character!", bg="white", fg="red").pack()

    result = zxcvbn(password)
    for k, v in result['crack_times_display'].items():
        tk.Label(time_frame, text=f"{k}: {v}", bg="white").pack()

    for suggestion in result['feedback']['suggestions']:
        tk.Label(suggestion_frame, text=suggestion, bg="white", fg="blue").pack()

    tk.Button(strength_window, text="Project Info", command=project_info).pack(pady=10)

# Input
def on_entry_click(event):
    if input_text.get() == "Enter Password to Check":
        input_text.delete(0, tk.END)
        input_text.config(fg='black')

button_frame = tk.Frame(root, bg="black")
button_frame.pack(pady=20)

input_text = tk.Entry(button_frame, font=("Arial", 14), bg="white", fg="grey", width=30)
input_text.insert(0, "Enter Password to Check")
input_text.bind('<FocusIn>', on_entry_click)
input_text.pack(side="left", padx=10)

check_button = tk.Button(button_frame, text="Check Strength", font=("Arial", 12), command=check_password)
check_button.pack(side="left")

info_button = tk.Button(root, text="Project Info", font=("Arial", 14, "bold"), bg="red", fg="white", command=project_info)
info_button.pack(pady=20)

project_label = tk.Label(root, text="Password Strength Checker!!!", font=("Arial", 20, "bold"), fg="white", bg="black")
project_label.pack(pady=20)

root.mainloop()
