from tkinter import *
from tkinter import messagebox
import base64

window = Tk()
window.title(" Secret Notes ")
window.config(padx=30,pady=30)

logo = PhotoImage(file="/Users/PC/Desktop/Python/ENC/icons8-top-secret-48.png")
logo_label = Label(image=logo)
#logo_label.config(width=100,height=100)
logo_label.pack()

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)



def save_text():
    title = title_entry.get()
    text = notes_text.get("1.0",END)
    master_key = master_entry.get()

    if len(title) == 0 or len(text) == 0 or len(master_key) == 0:
        messagebox.showerror(title="Fill the blank",message=" Please enter all info ")
    else:
        encrypted_text = encode(master_key,text)
        with open("/Users/PC/Desktop/Python/ENC/myfile.txt",mode="a") as myText:
            myText.write(f"\nTitle : {title}\n{encrypted_text}")

        

        title_entry.delete(0,END)
        notes_text.delete("1.0",END)
        master_entry.delete(0,END)


def show_text():
    encrypted_text = notes_text.get("1.0",END)
    master_key_decode = master_entry.get()

    if len(encrypted_text) == 0 or len(master_key_decode) == 0:
        messagebox.showerror(title="Fill the blank",message=" Please enter all info ")
    else:
        try:
            plain_text = decode(master_key_decode,encrypted_text)
            notes_text.delete("1.0",END)
            notes_text.insert(END,plain_text)
            master_entry.delete(0,END)
        except :
            messagebox.showerror(title="OPPss !! ",message=" Please enter encrypted text :) ")

title_label = Label(text="Enter your title")
title_label.pack()

title_entry = Entry(width=20)
title_entry.pack()

notes_label = Label(text="Enter your notes")
notes_label.pack()

notes_text = Text(width=25,height=10)
notes_text.pack()

master_label = Label(text="Enter your master key")
master_label.pack()

master_entry = Entry(width=20)
master_entry.pack()



save_button = Button(text=" Save and Encrypt ",command=save_text)
save_button.pack()

decrypted_button = Button(text=" Decrypt ",command=show_text)
decrypted_button.pack()


window.mainloop()