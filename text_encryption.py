
def Encryption(s,k):
    print(s)
    file1 = open(s, "r+")
    n=file1.read()
    print(n)
    print(k)
    
    encstr=""
    for i in n:
        if(ord(i))>=65 and (ord(i)<=90):
            temp=(ord(i)+k)
            if temp>90:
                temp=temp%90+64
            encstr=encstr+chr(temp)
        elif(ord(i))>=97 and (ord(i)<=122):
            temp=(ord(i)+k)
            if temp>122:
                temp=temp%122+96
            encstr=encstr+chr(temp)
        else:
            encstr=encstr+chr(ord(i)+k)
    return encstr
def Decryption(s,k):
    p=Encryption(s,k)
    decstr=""
    for i in p:
        if((ord(i))>=65) and (ord(i))<=90:
            decstr=decstr+chr((ord(i) - k-65) % 26 + 65)
        elif((ord(i))>=97) and (ord(i))<=122:
            decstr=decstr+chr((ord(i) - k - 97) % 26 + 97)
        else:
            decstr=decstr+chr(ord(i)-k)
    return decstr



# root=tk.Tk()

# root.title("IMAGE AND TEXT ENCRYPTION USING AES ALGORITHM")
# file1 = open("myfile.txt","r+") 
# s=file1.read()
# frame = tk.LabelFrame(root, text="", width=600, height=300, bd=5, font=('times', 14, ' bold '),bg="antiquewhite2")
# frame.grid(row=0, column=0, sticky='nw')
# frame.place(x=370, y=120)
# l2 = tk.Label(frame, text="Enter Key :", width=12, font=("Times new roman", 15, "bold"), bg="antiquewhite2",bd=5)
# l2.place(x=30, y=30)
# t1 = tk.Entry(frame, textvar=new_key, width=20, font=('', 15),bd=5)
# t1.place(x=230, y=30)
                    
# btn = tk.Button(frame, text="Encrypt", bg="red",font=("",20),fg="white", width=9, height=1, command=onClickEncrypt)
# btn.place(x=230, y=180)

# btn = tk.Button(frame, text="Decrypt", bg="red",font=("",20),fg="white", width=9, height=1, command=onClickEncrypt)
# btn.place(x=330, y=180)
