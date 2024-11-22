import smtplib
from email.message import EmailMessage
import imghdr

Sender_Email = "sheetalbitmap21@gmail.com"
Reciever_Email = "shital.sctcode@gmail.com"

Password ='Bitmap@123'
newMessage = EmailMessage()    #creating an object of EmailMessage class
newMessage['Subject'] = "Test Email from Smart Agriculture" #Defining email subject
newMessage['From'] = Sender_Email  #Defining sender email
newMessage['To'] = Reciever_Email  #Defining reciever email





newMessage.set_content('') #Defining email body
with open('abc.jpg', 'rb') as f:
    image_data = f.read()
    image_type = imghdr.what(f.name)
    image_name = f.name
newMessage.add_attachment(image_data, maintype='image', subtype=image_type, filename=image_name)
with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
    
    smtp.login(Sender_Email, Password)              
    smtp.send_message(newMessage)
