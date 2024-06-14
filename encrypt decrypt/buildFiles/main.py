from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def decrypt():
    global key, targetText
    key_value = key.get()
    if key_value == "":
        messagebox.showerror("Decryption", "Input Encryption Key")
        return

    try:
        cipher = AES.new(key_value.encode(), AES.MODE_ECB)
        encrypted_message = base64.b64decode(targetText.get("1.0", END).strip())
        decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
        
        decrypt_screen = Toplevel(screen)
        decrypt_screen.title("Decryption")
        decrypt_screen.geometry("400x200")
        decrypt_screen.configure(bg="#00bd56")

        Label(decrypt_screen, text="DECRYPT", font="lexend", fg="white", bg="#00bd56").place(x=5, y=0)
        text2 = Text(decrypt_screen, font=("Lexend", 12, "bold"), bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, decrypted_message)
    except Exception as e:
        if str(e) == "Padding is incorrect.":
            messagebox.showerror("Decryption", f"Wrong Encryption Key")
            return
        if str(e) == "Data must be aligned to block boundary in ECB mode":
            messagebox.showerror("Decryption", f"The message is not encrypted or wrong")
            return
        if str(e) == "Incorrect padding":
            messagebox.showerror("Decryption", f"The message is not encrypted or wrong")
            return
        messagebox.showerror("Decryption", f"Error: {e}")

def encrypt():
    global key, targetText
    key_value = key.get()
    if key_value == "":
        messagebox.showerror("encryption", "Input 16 Encryption Keys") 
        return
    
    try:
        cipher = AES.new(key_value.encode(), AES.MODE_ECB)
        padded_message = pad(targetText.get("1.0", END).strip().encode(), AES.block_size)
        encrypted_message = base64.b64encode(cipher.encrypt(padded_message)).decode()
        
        encrypt_screen =Toplevel(screen)
        encrypt_screen.title("Encryption")
        encrypt_screen.geometry("400x200")
        encrypt_screen.configure(bg="#ed3833")
        
        message = targetText.get(1.0,END)
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypt = base64_bytes.decode("ascii")
        
        Label(encrypt_screen, text="ENCRYPT", font="lexend", fg="white", bg="#ed3833").place(x=5,y=0)
        text2 = Text(encrypt_screen, font=("Lexend", 12, "bold"), bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10,y=40,width=380,height=150)
        
        text2.insert(END, encrypted_message)
    except ValueError as v:
        messagebox.showerror("Encryption", f"Input 16 Encryption Keys")
    except Exception as e:
        messagebox.showerror("Encryption", f"Error: {e}")
    
def main():
    
    global screen, key, targetText
    # Screen
    screen = Tk()
    screen.geometry("368x210")
    image_icon = PhotoImage(file="icon.png")
    screen.iconphoto(False, image_icon)
    screen.title("EncryptDecrypt")
    
    # reset button function
    def reset():
        key.set("")
        targetText.delete(1.0, END)
    
    # Target Text 
    Label(text="Enter text to encrypt or decrypt:", fg="black", font=("Lexend", 12, "bold")).place(x=5,y=0)
    targetText = Text(font=("Lexend", 11, "normal"), bg="white", relief=GROOVE, wrap=WORD, bd=1)
    targetText.place(x=5, y=30, width=355, height=50)
    
    # Encryption Key
    Label(text="Encryption key:", fg="black", font=("Lexend", 12, "bold")).place(x=5,y=85)
    key = StringVar()
    Entry(textvariable=key, width=230, bd=1, font=("Lexend", 11, "normal"), show="*").place(x=130, y=85, width=230, height=25)
    
    # Buttons
    Button(text="Encrypt", height="2", width=23, bg="#f44336", fg="white", bd=0, command=encrypt).place(x=10, y=120)
    Button(text="Decrypt", height="2", width=23, bg="#4CAF50", fg="white", bd=0, command=decrypt).place(x=194, y=120)
    Button(text="Reset", height="2", width=23, bg="#2196F3", fg="black", bd=0, command=reset).place(x=100, y=163)
    
    screen.mainloop()
    
main()