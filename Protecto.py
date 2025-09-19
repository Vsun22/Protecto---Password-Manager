import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
import tkinter as tk
from functools import partial
import uuid
import base64
import os
from PIL import Image, ImageTk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import customtkinter

backend = default_backend()   
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm = hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)
def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
encryptionkey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


#database
db = sqlite3.connect(r"Protecto.db")
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);               
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);               
""")

db.commit()

#popup
def popup(text):
    answer = simpledialog.askstring("input string", text)
    print(answer)

    return answer


#making window
window = Tk()
window.update()
window.title('PROTECTO')

icon = tk.PhotoImage(file='Resoures\Protecto3.png')
window.iconphoto(True, icon)

def hashPassword(input):
    hash1 = hashlib.sha256(input)
    hash1 = hash1.hexdigest()
    return hash1 

def firstScreen():
    for widget in window.winfo_children():
        widget.destroy() 

    window.geometry("728x400")
    window.resizable(False, False)
    bg_image = Image.open("Resoures\Snorlax.jpg")  
    bg = ImageTk.PhotoImage(bg_image)

    canvas = Canvas(window, width=700, height=400, highlightthickness=0)
    canvas.pack(fill="both", expand=False)
    canvas.create_image(0, 0, image=bg, anchor="nw")
    window.bg = bg  

    txt = Entry(window, font=("Arial", 20),bg="#444", fg='white',insertbackground='white')
    txt1 = Entry(window, font=("Arial", 20), bg="#444", fg='white', insertbackground='white')

    canvas.create_window(364, 125, window=txt) 

    canvas.create_window(364, 205, window=txt1) 

    canvas.create_text(364, 80, text="Enter Master Password",font='Arial', fill="white")
    canvas.create_text(384, 160, text="Re-Enter Master Password",font='Arial', fill="white")

    def SavePassword():
            if txt.get() == txt1.get():
                spl = 'DELETE FROM masterpassword WHERE id = 1'

                cursor.execute(spl)

                master_hashed_password = hashPassword(txt.get().encode('utf-8'))
                key = str(uuid.uuid4().hex)

                global encryptionkey
                encryptionkey = derive_key(txt.get())

                insert_password = """INSERT INTO masterpassword(password)
                VALUES(?)"""
                cursor.execute(insert_password, (master_hashed_password,))
                db.commit()
                passwordVault()
            else:
                lbl.config(text='Password not the same')
    btn = Button(window, text='Submit', command=SavePassword, bg="#444", fg="white", font=("Arial", 12))
    canvas.create_window(350, 260, window=btn)
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    
    bg_image = Image.open("Resoures\Abra.jpg")  
    bg = ImageTk.PhotoImage(bg_image)
    icon = tk.PhotoImage(file='Resoures\Protecto3.png')
    window.iconphoto(True, icon)

    canvas = Canvas(window, width=700, height=400, highlightthickness=0)
    canvas.pack(fill="both", expand=False)
    canvas.create_image(0, 0, image=bg, anchor="nw")
    window.bg = bg  

    window.geometry("700x400")
    window.resizable(False, False)
    
    canvas.create_text(340, 80, text="Enter Master Password", font=("Arial", 20), fill="white")
    txt = Entry(window, width=20, show="*", font=("Arial", 20),bg="#444", fg="white", insertbackground="white")
    canvas.create_window(340, 130, window=txt)
    lbl1 = Label(window, text="", fg="red", bg="#444", font=("Arial", 12))
    

    def getMasterpassword():
        checkhashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionkey
        encryptionkey = derive_key(txt.get())
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [checkhashedPassword])
        return cursor.fetchall()
    
    def checkPassword():
        password = getMasterpassword()
        if password:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong password!')

    btn = Button(window, text='Submit', command=checkPassword, bg="#444", fg="white", font=("Arial", 12))
    canvas.create_window(340, 200, window=btn)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    bg_image = Image.open(r'Resoures\Ditto.jpg')  
    bg = ImageTk.PhotoImage(bg_image)

    icon = tk.PhotoImage(file='Resoures/Protecto3.png')
    window.iconphoto(True, icon)

    canvas = Canvas(window, width=700, height=400, highlightthickness=0)
    canvas.pack(fill="both")
    canvas.create_image(0, 0, image=bg, anchor="nw")
    window.bg = bg  

    Scroll = Frame(window, bg="#444")
    Scroll.place(relx=0.5, rely=0.5, anchor="center")

    scroll_canvas = Canvas(Scroll, bg="#444", width=650, height=300, highlightthickness=0)
    scrollbar = Scrollbar(Scroll, orient="vertical", command=scroll_canvas.yview)
    frame = Frame(scroll_canvas, bg="#444")

    frame.bind("<Configure>", lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all")))

    scroll_canvas.create_window((0, 0), window=frame, anchor="nw")
    scroll_canvas.configure(yscrollcommand=scrollbar.set)

    scroll_canvas.pack(side="left", fill="both")
    scrollbar.pack(side="right", fill="y")

    
    lbl = customtkinter.CTkLabel(frame, text='Password Vault', font=("Arial", 16))
    lbl.grid(column=1, row=0, pady=10)

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = encrypt(popup(text1).encode(), encryptionkey)
        username = encrypt(popup(text2).encode(), encryptionkey)
        password = encrypt(popup(text3).encode(), encryptionkey)

        insert_field = """INSERT INTO vault(website,username,password)
        VALUES(?, ?, ?)"""
        cursor.execute(insert_field, (website, username, password))
        db.commit()

        passwordVault()

    def removeEntry(input):
        cursor.execute('DELETE FROM vault WHERE id = ?', (input,))
        db.commit()
        passwordVault()

    window.geometry('700x400')
    window.resizable(False, False)

    lbl = customtkinter.CTkLabel(frame, text='Protecto Password Vault', font=("Arial", 16))
    lbl.grid(column=1, row=0, pady=10)

    btn = customtkinter.CTkButton(frame, text="+", command=addEntry, width=50)
    btn.grid(column=1, row=1, pady=10)

    customtkinter.CTkLabel(frame, text='Website', font=("Arial", 12)).grid(row=2, column=0, padx=60)
    customtkinter.CTkLabel(frame, text='Username', font=("Arial", 12)).grid(row=2, column=1, padx=60)
    customtkinter.CTkLabel(frame, text='Password', font=("Arial",12)).grid(row=2, column=2, padx=60)

    cursor.execute('SELECT * FROM vault')
    rows = cursor.fetchall()

    if rows:
        for i, row in enumerate(rows):
            website = decrypt(row[1], encryptionkey).decode('utf-8')
            username = decrypt(row[2], encryptionkey).decode('utf-8')
            password = decrypt(row[3], encryptionkey).decode('utf-8')

            Label(frame, text=website, font=('Poppins', 12), bg="#444", fg="white").grid(column=0, row=(i+3))
            Label(frame, text=username, font=('Poppins', 12), bg="#444", fg="white").grid(column=1, row=(i+3))
            Label(frame, text=password, font=('Poppins', 12), bg="#444", fg="white").grid(column=2, row=(i+3))

            Button(frame, text='Delete', command=partial(removeEntry, row[0]), bg="maroon", fg="white", font=("Arial", 10)).grid(column=3, row=(i+3), pady=5, padx=10)



            i = i +1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    firstScreen()

window.mainloop()



