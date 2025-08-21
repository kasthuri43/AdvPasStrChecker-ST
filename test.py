import tkinter as tk
from tkinter import ttk, messagebox
import random, string, re
import tempfile
import webbrowser
import hashlib
import requests

def load_common_passwords(filepath="common-passwords.txt"):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            common_passwords = {line.strip().lower() for line in f if line.strip()}
        return common_passwords
    except FileNotFoundError:
        # Fallback small set if file not found
        return {"123456", "password", "123456789", "qwerty", "abc123", "111111", "123123", "admin"}

COMMON_PASSWORDS = load_common_passwords()

def password_strength(pw):
    length = len(pw)
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(c in string.punctuation for c in pw)
    score = length + sum([has_upper, has_lower, has_digit, has_special]) * 5
    if score < 10:
        return score, "Very Weak", "red", "Instant"
    elif score < 15:
        return score, "Weak", "orange", "Seconds"
    elif score < 20:
        return score, "Moderate", "gold", "Hours"
    elif score < 25:
        return score, "Strong", "green", "Days"
    else:
        return score, "Very Strong", "darkgreen", "Years"

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def check_pwned_password(password):
    sha1_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_pw[:5]
    suffix = sha1_pw[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url)
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return True, int(count)
        return False, 0
    except Exception:
        return False, 0

def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.state('zoomed')
        self.configure(bg="black")
        self.password_var = tk.StringVar()
        self.generated_var = tk.StringVar()
        self.password_length = 12

        self.canvas = tk.Canvas(self, bg="black", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", self.repaint_background)

        self.main = tk.Frame(self.canvas, bg="black")
        self.main_id = self.canvas.create_window((self.winfo_screenwidth()//2, 100), window=self.main, anchor="n")

        self.build_ui()

    def repaint_background(self, event=None):
        self.canvas.delete("tile")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        tile = 40
        icons = ["🔒","🛡️","🔑"]
        font = ("Segoe UI Emoji", 14)
        for y in range(0, h, tile):
            offset = (y//tile) % 2 * (tile//2)
            for x in range(0, w, tile):
                icon = icons[(x//tile + y//tile) % len(icons)]
                self.canvas.create_text(x+offset, y, text=icon, font=font, fill="#333333", tag="tile")
        self.canvas.coords(self.main_id, w//2, 100)

    def build_ui(self):
        tk.Label(self.main, text=" Advanced Password Strength Checker", font=("Segoe UI", 20, "bold"),
                 fg="white", bg="black").pack(pady=(20,10))

        ttk.Entry(self.main, textvariable=self.password_var, font=("Segoe UI",14), width=30).pack(ipady=5, pady=(0,15))

        btns = tk.Frame(self.main, bg="black")
        btns.pack(pady=5)

        tk.Button(btns, text="🔒 Check Strength", fg="white",
                  font=("Segoe UI",14,"bold"), relief="flat", padx=12, pady=8,
                  bg="#5b078b", activebackground="#34064e", command=self.check_password).pack(side="left", padx=8)

        tk.Button(btns, text="📄 Project Info", fg="white",
                  font=("Segoe UI",14,"bold"), relief="flat", padx=12, pady=8,
                  bg="#d67316", activebackground="#f57308", command=self.open_project_info).pack(side="left", padx=8)

        ttk.Entry(self.main, textvariable=self.generated_var, font=("Segoe UI",14),
                  width=30, state="readonly").pack(ipady=5, pady=(25,5))

        tk.Button(self.main, text="+", fg="white",
                  font=("Segoe UI",20,"bold"), relief="flat", padx=16, pady=4,
                  bg="#171b3f", activebackground="#050624", command=self.toggle_fab).pack(pady=15)

        self.fab_menu = tk.Frame(self.main, bg="black")
        self.fab_shown = False
        options = [("🔢 Set Length", self.set_length),
                   ("📋 Copy Password", self.copy_pass),
                   ("🔑 Generate Password", self.generate_pass),
                   ("📃 Generate Multiple Passwords", self.generate_multiple_passwords)]
        for text, cmd in options:
            btn = tk.Button(self.fab_menu, text=text, bg="#444444", fg="white",
                            font=("Segoe UI",12,"bold"), relief="flat", padx=10, pady=6,
                            activebackground="#666666", command=cmd)
            btn.pack(fill="x", pady=3)

    def toggle_fab(self):
        if self.fab_shown:
            self.fab_menu.pack_forget()
        else:
            self.fab_menu.pack(pady=5)
        self.fab_shown = not self.fab_shown

    def copy_pass(self):
        pw = self.generated_var.get()
        if pw:
            self.clipboard_clear()
            self.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Nothing to copy.")

    def set_length(self):
        win = tk.Toplevel(self)
        win.title("Set Password Length")
        win.geometry("300x150")
        win.configure(bg="black")
        var = tk.IntVar(value=self.password_length)
        ttk.Label(win, text="Password length (6–32):", background="black",
                  foreground="white", font=("Segoe UI",12)).pack(pady=10)
        ttk.Entry(win, textvariable=var, font=("Segoe UI",14)).pack(ipady=5)

        def save():
            val = var.get()
            if 6 <= val <= 32:
                self.password_length = val
                messagebox.showinfo("Saved", f"Length set to {val}")
                win.destroy()
            else:
                messagebox.showerror("Invalid", "Length must be between 6 and 32")

        ttk.Button(win, text="Save", command=save).pack(pady=10)

    def generate_pass(self):
        pw = generate_password(self.password_length)
        self.generated_var.set(pw)
        messagebox.showinfo("Generated", "Password created!")

    def generate_multiple_passwords(self):
        win = tk.Toplevel(self)
        win.title("Generate Multiple Passwords")
        win.geometry("400x400")
        win.configure(bg="black")

        ttk.Label(win, text="Number of Passwords (3 to 5):", background="black", foreground="white").pack(pady=10)
        num_var = tk.IntVar(value=3)
        ttk.Entry(win, textvariable=num_var, font=("Segoe UI",12)).pack(ipady=3)

        text_area = tk.Text(win, font=("Segoe UI", 12), height=10, width=40)
        text_area.pack(pady=10)

        def generate_and_display():
            n = num_var.get()
            if 3 <= n <= 5:
                text_area.delete("1.0", tk.END)
                pwds = [generate_password(self.password_length) for _ in range(n)]
                for pwd in pwds:
                    text_area.insert(tk.END, pwd + "\n")
            else:
                messagebox.showerror("Invalid", "Choose between 3 and 5")

        def copy_to_clipboard():
            text = text_area.get("1.0", tk.END).strip()
            if text:
                self.clipboard_clear()
                self.clipboard_append(text)
                messagebox.showinfo("Copied", "All passwords copied to clipboard.")

        ttk.Button(win, text="Generate", command=generate_and_display).pack(pady=5)
        ttk.Button(win, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=5)

    def check_password(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Input Needed", "Please enter a password.")
            return

        score, status, color, crack_time = password_strength(password)
        common = is_common_password(password)
        pwned, count = check_pwned_password(password)

        strength_window = tk.Toplevel(self)
        strength_window.title("Password Strength Details")
        strength_window.geometry("600x500")
        strength_window.configure(bg='black')

        tk.Label(strength_window, text=f"Your Password: {password}", fg="white", bg="black",
                 font=("Segoe UI", 14, "bold")).pack(pady=10)

        canvas_size = 250
        canvas = tk.Canvas(strength_window, width=canvas_size, height=canvas_size, bg='black', highlightthickness=0)
        canvas.pack(pady=40)

        center = canvas_size // 2
        radius = 80
        canvas.create_oval(center-radius, center-radius, center+radius, center+radius, outline="#444", width=20)

        max_score = 30
        extent = (score / max_score) * 360
        if extent > 360:
            extent = 360
        canvas.create_arc(center-radius, center-radius, center+radius, center+radius,
                          start=90, extent=-extent, style='arc', outline=color, width=20)

        canvas.create_text(center, center, text=status, fill=color, font=("Segoe UI", 20, "bold"))

        crack_label = tk.Label(strength_window, text=f"Estimated Crack Time: {crack_time}",
                               fg=color, bg="black", font=("Segoe UI", 12, "italic"))
        crack_label.pack(pady=5)

        req_frame = tk.Frame(strength_window, bg="black")
        req_frame.pack(pady=20, fill="x", padx=50)

        checks = {
            "At least 8 characters": len(password) >= 8,
            "Contains uppercase letter": any(c.isupper() for c in password),
            "Contains lowercase letter": any(c.islower() for c in password),
            "Contains digit": any(c.isdigit() for c in password),
            "Contains special character": any(c in string.punctuation for c in password)
        }

        tk.Label(req_frame, text="Password Requirements:", fg="white", bg="black", font=("Segoe UI", 14, "underline")).pack(anchor="w")

        for req, passed in checks.items():
            color_text = "green" if passed else "red"
            prefix = "✓" if passed else "✗"
            tk.Label(req_frame, text=f"{prefix} {req}", fg=color_text, bg="black", font=("Segoe UI", 12)).pack(anchor="w", padx=20)

        if pwned:
            tk.Label(strength_window, text=f"❌ Found in {count} data breaches!", fg="red", bg="black", font=("Segoe UI", 12, "bold")).pack(pady=5)
        else:
            tk.Label(strength_window, text="✔️ Not found in known data breaches.", fg="green", bg="black", font=("Segoe UI", 12)).pack(pady=5)

        if common:
            tk.Label(strength_window, text="⚠️ This password is very common!", fg="orange", bg="black", font=("Segoe UI", 12)).pack(pady=5)
        else:
            tk.Label(strength_window, text="✔️ This password is not commonly used.", fg="lightgreen", bg="black", font=("Segoe UI", 12)).pack(pady=5)
    def open_project_info(self):
        import os  # Required for opening the local HTML file

        with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode='w', encoding='utf-8') as f:
            html_content = """
            <html>
            <head>
                <title>Project Information</title>
                <style>
                    body { font-family: Arial; margin: 20px; background-color: black; color: white; }
                    h1 { text-align: left; }
                    table { border-collapse: collapse; width: 100%; margin-top: 10px; color: white; }
                    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
                    th { background: #333333; }
                    .section-title { margin-top: 30px; font-size: 18px; font-weight: bold; color: #f2f2f2; }
                </style>
            </head>
            <body>
                <h1>Project Information</h1>
                <p>This project was developed by <strong>Kasthuri&Team</strong> as part of a Ethical Hacking&Cyber Security Internship. It is designed to ensure robust security by evaluating password strength against modern threats and best practices.</p>

                <div class="section-title">Project Details</div>
                <table>
                    <tr><th>Project Name</th><td> Advanced Password Strength Checker</td></tr>
                    <tr><th>Description</th><td>Detects common patterns, and provides real-time feedback to enhance security.</td></tr>
                    <tr><th>Start Date</th><td>26-MAY-2025</td></tr>
                    <tr><th>End Date</th><td>09-AUGUST-2025</td></tr>
                    <tr><th>Status</th><td>Completed</td></tr>
                </table>

                <div class="section-title">Developer Details</div>
                <table>
                    <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
                    <tr><td>Geetha sai vineetha</td><td>ST#IS#7748</td><td>geethasai156@gmail.com</td></tr>
                    <tr><td>Kasthuri</td><td>ST#IS#7749</td><td>kasthurianakapalli@gmail.com</td></tr>
                    <tr><td>Deepika</td><td>ST#IS#7751</td><td>deepikabattula236@gmail.com</td></tr>
                    <tr><td>Deepthi</td><td>ST#IS#7752</td><td>deepthiveeravarapu@gmail.com</td></tr>
                    <tr><td>Manjula</td><td>ST#IS#7753</td><td>manjusiva1981@gmail.com</td></tr>

                </table>

                <div class="section-title">Company Details</div>
                <table>
                    <tr><th>Name</th><td>Supraja Technologies</td></tr>
                    <tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
                </table>
            </body>
            </html>
            """
            f.write(html_content)
            webbrowser.open('file://' + os.path.realpath(f.name))


if __name__ == "__main__":
    App().mainloop()