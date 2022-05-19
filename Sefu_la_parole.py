import sqlite3 #used for the database
import hashlib

# Import GUI
from tkinter import *
from tkinter import simpledialog #simpledialog is used for the popup


from functools import partial

import uuid
import pyperclip #Copy tool
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

a_count = 0
a_count_2 = 0
encryptionKey = 0

#Encrypt function
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

#Decrypt function
def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Database:
with sqlite3.connect("Password_Vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
Website TEXT NOT NULL,
Username TEXT NOT NULL,
Password TEXT NOT NULL);
""")


# Create POPUP
def popUp(text):
    answer = simpledialog.askstring("Input String", text)
    return answer


# Delete Widgets Function
def deleteWidgets():
    for widget in window.winfo_children():
        widget.destroy()


# Window
window = Tk()

window.title("Seif Parole")

#The hashing of a password
def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash

#The first screen in which you set the password
def firstScreen():
    deleteWidgets()

    window.geometry("250x250")

    def unshow_show_Password(): #A function that hides or unhides the text input

        global a_count

        if a_count % 2 == 0:
            txt.config(show="*")
            txt_1.config(show="*")
        else:
            txt.config(show="")
            txt_1.config(show="")
        a_count = a_count + 1

    lbl = Label(window, text="Creaza Parola Principala")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl_1 = Label(window, text="Reintrodu Parola")
    lbl_1.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl_2 = Label(window, text="Reintrodu Parola")
    lbl_2.pack()

    txt_1 = Entry(window, width=20)
    txt_1.pack()

    btn = Button(window, text="UnShow/Show", command=unshow_show_Password)
    btn.pack()

    def savePassword():
        if txt.get() == txt_1.get():

            sql = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode("utf-8"))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode("utf-8"))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?)"""
            cursor.execute(insert_password, [(hashedPassword), (recoveryKey)])
            db.commit()

            recoveryScreen(key)
        else:
            lbl_1.config(text="Passwords do not match")

    btn = Button(window, text="Save Password", command=savePassword)
    btn.pack(pady=10)

#Creates the window recovery screen
def recoveryScreen(key):
    deleteWidgets()

    window.geometry("250x150")

    lbl = Label(window, text="Save this key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl_1 = Label(window, text=key)
    lbl_1.pack()

    def copyKey():
        pyperclip.copy(lbl_1.cget("text"))

    btn = Button(window, text="Copy Key", command=copyKey)
    btn.pack(pady=10)

    def done():
        passwordVault()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=10)

#Create the window reset screen
def resetScreen():
    deleteWidgets()

    window.geometry("250x150")

    lbl = Label(window, text="Enter Recovery key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl_1 = Label(window)
    lbl_1.config(anchor=CENTER)
    lbl_1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode("utf-8"))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?", [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()
        if checked:
            firstScreen()
        else:
            txt.delete(0, 'end')
            lbl_1.config(text="Wrong Key")

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=10)

#Creates the main screen
def loginScreen():
    window.geometry("350x350")

    def unshow_show_Password(): #A function that hides or unhides the text input

        global a_count_2

        if a_count_2 % 2 == 0:
            txt.config(show="*")
        else:
            txt.config(show="")
        a_count_2 = a_count_2 + 1

    lbl = Label(window, text="Introdu Parola Principala")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl_1 = Label(window)
    lbl_1.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()  # Selecteaza deja casuta

    btn = Button(window, text="UnShow/Show", command=unshow_show_Password)
    btn.pack(pady=20)

    lbl_1 = Label(window)
    lbl_1.pack()

    def getMasterPassword():
        checkedHashPassword = hashPassword(txt.get().encode("utf-8"))

        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

        cursor.execute("SELECT * FROM masterpassword WHERE ID = 1 AND password = ?", [(checkedHashPassword)])
        print(checkedHashPassword)
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        print(match)

        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl_1.config(text="Parola Gresita")

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)  # lasa x spatiu, valoarea lui pady

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=10)

#The actual password vault
def passwordVault():
    deleteWidgets()

    def addEntry():
        text_1 = "Website"
        text_2 = "Username"
        text_3 = "Password"

        website = encrypt(popUp(text_1).encode(), encryptionKey)
        username = encrypt(popUp(text_2).encode(), encryptionKey)
        password = encrypt(popUp(text_3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?,?,?)"""

        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    window.geometry("800x350")

#Creating a frame
    main_frame = Frame(window)
    main_frame.pack(fill=BOTH,expand = 1)

#Creating a canvas
    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand = 1)

#Creating the scrollbar
    scrl = Scrollbar(main_frame, orient = VERTICAL, command=my_canvas.yview)
    scrl.pack(side=RIGHT, fill = Y)

#Configure canvas
    my_canvas.configure(yscrollcommand=scrl.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion = my_canvas.bbox("all")))

#Creating second frame
    second_frame = Frame(my_canvas)

#Add new frame to a new window in canvas(here all the buttons and lbl and text)
    my_canvas.create_window((0, 0), window = second_frame, anchor="nw")


    lbl = Label(second_frame, text="SEIF PAROLE")
    lbl.grid(column=1)

    btn = Button(second_frame, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(second_frame, text="Website:")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(second_frame, text="Username:")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(second_frame, text="Password:")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            lbl_1 = Label(second_frame, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl_1.grid(column=0, row=i + 3)
            lbl_1 = Label(second_frame, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl_1.grid(column=1, row=i + 3)
            lbl_1 = Label(second_frame, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl_1.grid(column=2, row=i + 3)

            btn = Button(second_frame, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()
