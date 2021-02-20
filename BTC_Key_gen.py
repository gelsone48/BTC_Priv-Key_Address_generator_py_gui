import tkinter as tk
import tkinter.font as tkFont
from tkinter import messagebox
from bit import Key
from utils import g, b58encode, b58decode
from binascii import hexlify, unhexlify
from struct import Struct
import hashlib
PACKER = Struct('>QQQQ')


class App:
    def __init__(self, root):
        #setting title
        root.title("BitCoin address generator")
        root.iconbitmap('btc.ico')
        global GLineEdit_557,GLabel_342,GLabel_693,GLabel_957
        #setting window size
        width=600
        height=500
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        GButton_206=tk.Button(root)
        GButton_206["activebackground"] = "#90ee90"
        GButton_206["anchor"] = "center"
        GButton_206["bg"] = "#efefef"
        ft = tkFont.Font(family='Times',size=10)
        GButton_206["font"] = ft
        GButton_206["fg"] = "#000000"
        GButton_206["justify"] = "center"
        GButton_206["text"] = "Generate"
        GButton_206["relief"] = "ridge"
        GButton_206.place(x=460,y=80,width=109,height=51)
        GButton_206["command"] = GButton_206_command

        GLineEdit_557=tk.Entry(root)
        GLineEdit_557["borderwidth"] = "1px"
        ft = tkFont.Font(family='Times',size=10)
        GLineEdit_557["font"] = ft
        GLineEdit_557["fg"] = "#333333"
        GLineEdit_557["justify"] = "center"
        GLineEdit_557["text"] = "Entry"
        GLineEdit_557.place(x=10,y=80,width=440,height=51)

        GLabel_342=tk.Label(root)
        GLabel_342["activebackground"] = "#999999"
        ft = tkFont.Font(family='Times',size=10)
        GLabel_342["font"] = ft
        GLabel_342["fg"] = "#e62a2a"
        GLabel_342["justify"] = "center"
        GLabel_342["text"] = "Primary key"
        GLabel_342.place(x=10,y=210,width=561,height=51)

        GLabel_693=tk.Label(root)
        GLabel_693["activebackground"] = "#999999"
        ft = tkFont.Font(family='Times',size=10)
        GLabel_693["font"] = ft
        GLabel_693["fg"] = "#1760f1"
        GLabel_693["justify"] = "center"
        GLabel_693["text"] = "Address"
        GLabel_693.place(x=10,y=300,width=562,height=51)

        GLabel_573=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_573["font"] = ft
        GLabel_573["fg"] = "#333333"
        GLabel_573["justify"] = "center"
        GLabel_573["text"] = "Balance: "
        GLabel_573.place(x=10,y=400,width=70,height=38)

        GLabel_957=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_957["font"] = ft
        GLabel_957["fg"] = "#009688"
        GLabel_957["justify"] = "center"
        GLabel_957["text"] = "value"
        GLabel_957.place(x=250,y=400,width=70,height=25)

        GLabel_453=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_453["font"] = ft
        GLabel_453["fg"] = "#333333"
        GLabel_453["justify"] = "center"
        GLabel_453["text"] = "Private key"
        GLabel_453.place(x=10,y=210,width=70,height=25)

        GLabel_452=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_452["font"] = ft
        GLabel_452["fg"] = "#333333"
        GLabel_452["justify"] = "center"
        GLabel_452["text"] = "Address"
        GLabel_452.place(x=0,y=300,width=70,height=25)
        
        GLabel_356=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_356["font"] = ft
        GLabel_356["fg"] = "#333333"
        GLabel_356["justify"] = "center"
        GLabel_356["text"] = "Enter a number "
        GLabel_356.place(x=0,y=50,width=132,height=30)

def GButton_206_command():
	try:
		pkey=int_to_address(int(GLineEdit_557.get()))
		GLabel_342.config(text=str(pkey))
		address_1 = Key(pkey)
		GLabel_693.config(text=str(address_1).strip("<PrivateKey: >" ))
		add_val=address_1.get_balance()
		GLabel_957.config(text=str(add_val))
	except:
		messagebox.showinfo("Worng Entry Value","Please enter a number between 0 and 999*  X99")
		


   # print("2")
	#GMessage_855.config(text="22222")

def base58_check_encode(prefix, payload, compressed=False):
    # Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    s = prefix + payload
    if compressed:
        s = prefix + payload + b'\x01'

    # Add the 4 checksum bytes at the end of extended RIPEMD-160 hash. This is the 25-byte binary Bitcoin Address.
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]

    result = s + checksum

    return '1' * count_leading_zeroes(result) + b58encode(result).decode()   
def count_leading_zeroes(s):
    count = 0
    for c in s:
        if c == '\0':
            count += 1
        else:
            break
    return count

def int_to_address(number):
    number0 = number >> 192
    number1 = (number >> 128) & 0xffffffffffffffff
    number2 = (number >> 64) & 0xffffffffffffffff
    number3 = number & 0xffffffffffffffff

    private_key = hexlify(PACKER.pack(number0, number1, number2, number3)).decode("utf-8")
    compressed_key = base58_check_encode(b'\x80', unhexlify(private_key), True)
    #print(compressed_key)
    return compressed_key
    
    
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
