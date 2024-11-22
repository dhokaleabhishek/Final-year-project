# -*- coding: utf-8 -*-ss
"""
Created on Tue May  4 17:28:41 2021

@author: user
"""

from tkinter import *
import tkinter as tk


from PIL import Image ,ImageTk

from tkinter.ttk import *
from pymsgbox import *


root=tk.Tk()

root.title("Image and Text deduplication In cloud")

#, relwidth=1, relheight=1)

w = tk.Label(root, text="Image and Text deduplication In cloud",width=40,background="skyblue",height=2,font=("Times new roman",19,"bold"))
w.place(x=0,y=15)



w,h = root.winfo_screenwidth(),root.winfo_screenheight()
root.geometry("%dx%d+0+0"%(w,h))
root.configure(background="skyblue")


from tkinter import messagebox as ms


def Login():
    from subprocess import call
    call(["python","Login1.py"])
    #frame_alpr = tk.LabelFrame(root, text=" --Login Page-- ", width=350, height=350, bd=5, font=('times', 14, ' bold '),bg="blue2")
    #frame_alpr.grid(row=0, column=0, sticky='nw')
    #frame_alpr.place(x=300, y=200)


def Register():
   # ms.showinfo('Detective System', 'Diverting To Diabetes Detection System. It may take time to load and start system!!')
    from subprocess import call
    call(["python","registration.py"])






bg = Image.open(r"bg.png")
bg.resize((1700,700))
print(w,h)
bg_img = ImageTk.PhotoImage(bg)
bg_lbl = tk.Label(root,image=bg_img)
bg_lbl.place(x=0,y=0)
#wlcm=tk.Label(root,text="Bitcoin Price Prediction System Using Machine Learning",width=85,height=2,background="#151B54",foreground="white",font=("Times new roman",22,"bold"))
#wlcm.place(x=0,y=0)

#choose = "_________________________________Choose Options From Below_________________________________"
#co=tk.Label(root,text=choose,width=95,height=2,background="cyan2",foreground="black",font=("Tempus Sans ITC",19,"bold"))
#co.place(x=0,y=50)

wlcm=tk.Label(root,text="......Welcome to Image and Text deduplication In cloud ......",width=85,height=2,background="skyblue",foreground="black",font=("Times new roman",22,"bold"))
wlcm.place(x=0,y=620)




Disease2=tk.Button(root,text="Login",command=Login,width=9,height=2,bd=0,background="skyblue",foreground="black",font=("times new roman",14,"bold"))
Disease2.place(x=1100,y=18)


Disease3=tk.Button(root,text="Register",command=Register,width=9,height=2,bd=0,background="skyblue",foreground="black",font=("times new roman",14,"bold"))
Disease3.place(x=1200,y=18)




root.mainloop()
