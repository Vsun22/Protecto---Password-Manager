
from tkinter import *
from PIL import Image, ImageTk
from random import randint
import tkinter as tk
import secrets
import string 

batman = Tk()
batman.title("Password Generator")
batman.geometry("728x410")
batman.resizable(False, False)

image = Image.open(r"Resoures\LUCARIO.jpg")
bg = ImageTk.PhotoImage(image)

icon = tk.PhotoImage(file='Resoures\Protecto3.png')
batman.iconphoto(True, icon)

canvas = Canvas(batman, width=728, height=410)
canvas.pack()
canvas.create_image(0, 0, image=bg, anchor="nw")


def value():
    ent2.delete(0, END)
    length = int(ent1.get())
    pssh = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm" + "1234567890" + "!@#$%^&*()-+="
    password = ''.join(secrets.choice(pssh) for i in range(length))
    ent2.insert(0, password)

def copy():
    batman.clipboard_clear()
    batman.clipboard_append(ent2.get())


ent1 = Entry(batman, bg="#444", fg='white', font=("Arial", 20))
ent2 = Entry(batman, bg="#444", fg='white', font=("Arial", 20))

canvas.create_window(364, 85, window=ent1) 
canvas.create_window(364, 165, window=ent2) 

canvas.create_text(364, 40, text="Password Length", font='Arial', fill="white")

gen = Button(batman, text="Generate", command=value, bg="#444", fg="white", font=("Arial", 14))
btn = Button(batman, text="Copy", command=copy, bg="#444", fg="white", font=("Arial", 14))

canvas.create_window(270, 250, window=gen)
canvas.create_window(460, 250, window=btn)
batman.mainloop()
