
from tkinter import *
from PIL import Image, ImageTk
from random import randint
import tkinter as tk

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


def new_rand():
    ent2.delete(0, END)
    length = int(ent1.get())
    if length <= 0:
            ent2.insert(0, "Enter a positive number")
        

    password = ''.join(chr(randint(33, 126)) for _ in range(length))
    ent2.insert(0, password)

def copy_to_clipboard():
    batman.clipboard_clear()
    batman.clipboard_append(ent2.get())


ent1 = Entry(batman, bg="#444", fg='white', font=("Arial", 20), bd=0)
ent2 = Entry(batman, bg="#444", fg='white', font=("Arial", 20), bd=0)

canvas.create_window(364, 85, window=ent1) 
canvas.create_window(364, 165, window=ent2) 

canvas.create_text(364, 40, text="Password Length",font='Arial', fill="white")

btn_generate = Button(batman, text="Generate", command=new_rand, bg="#444", fg="white", font=("Arial", 14),)
btn_copy = Button(batman, text="Copy", command=copy_to_clipboard,bg="#444", fg="white", font=("Arial", 14),  )

canvas.create_window(270, 250, window=btn_generate,)
canvas.create_window(460, 250, window=btn_copy)

# ------------------ Run App ------------------
batman.mainloop()
