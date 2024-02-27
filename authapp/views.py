from django.shortcuts import render,HttpResponse,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from authapp.utils import TokenGenerator,generate_token
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from django.views.generic import View
from django.urls import NoReverseMatch,reverse
from django.core.mail import send_mail,EmailMultiAlternatives
from django.core.mail import BadHeaderError
from django.core import mail
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.

def index(request):
    return render(request,'index.html')
import threading

#email thread use to take less time to send email thats why we use that
class EmailThread(threading.Thread):
    def __init__(self,email_message):
        self.email_message=email_message
        threading.Thread.__init__(self)
    def run(self):
        self.email_message.send()
def signup(request):
    if request.method=="POST":
        user_email=request.POST['signup-email']
        user_password=request.POST['signup-pass']
        user_confirmpassword=request.POST['signup-conpass']

        if user_password!=user_confirmpassword:
            messages.warning(request,"password is not matching")
            return render('auth/signup.html')
        try:
            if User.objects.get(username=user_email):
                messages.warning(request,"email already taken")
                return render(request,"auth/signup.html")
        except Exception as identifier:
            pass
        my_user=User.objects.create_user(user_email,user_email,user_password)
        my_user.is_active=False
        #my_user.save()
        #return redirect('/authapp/login')
        current_site=get_current_site(request)
        email_subject="Activate your account"
        message=render_to_string('auth/activate.html',{
            'signup_user':my_user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(my_user.pk)),
            'token':generate_token.make_token(my_user)
        })

        email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[user_email])
        EmailThread(email_message).start()
        #email_message.send()
        messages.success(request,"Activate your accout by clicking the link in your gmail")
        return redirect('/authapp/login')
    return render(request,'auth/signup.html')

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            #decode_user coming from generate token utils.py file
            decode_user=User.objects.get(pk=uid)
        except Exception as identifier:
            decode_user=None
            print("coming here..........................")
        if decode_user is not None and generate_token.check_token(decode_user,token):
            decode_user.is_active=True
            decode_user.save()
            messages.success(request,"Acount activated succesfully")
            return redirect('/authapp/login')
        return render(request,'auth/login.html')

def handlelogin(request):
    if request.method=="POST":
        loginUserEmail=request.POST['login-email']
        userPassword=request.POST['login-pass']

        loginUser=authenticate(username=loginUserEmail,password=userPassword)

        if loginUser is not None:
            login(request,loginUser)
            messages.success(request,"Login successfull")
            return render(request,"index.html")
        
        else:
            messages.error(request,"something went wrong")
            return redirect('authapp/login')
    return render(request,"auth/login.html")


def logout(request):
    pass

class RequestResetEmailView(View):
    def get(self,request):
        return render(request,"auth/request-reset-email.html")
    def post(self,request):
        email_for_reset_password=request.POST['enter_email']
        reset_user=User.objects.filter(email=email_for_reset_password)

        if reset_user.exists():
            current_site=get_current_site(request)
            email_subject="Reset Your Password"
            message=render_to_string('auth/reset-user-password.html',{
                'user':'reset_user',
                'domain':'127.0.0.1:8000',
                'uid':urlsafe_base64_encode(force_bytes(reset_user[0].pk)),
                'token':PasswordResetTokenGenerator().make_token(reset_user[0])
            })

            email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email_for_reset_password])
            EmailThread(email_message).start()
            messages.info(request,"we have sent a link in your email to reset your password")
            return render(request,"auth/request-reset-email.html")

class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"Password Reset Link is Invalid")
                return render(request,'auth.request-reser-email.html')
        except DjangoUnicodeDecodeError as identifier:
            pass

        return render(request,'auth/set-new-password.html',context)
    def post(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token,
        }
        new_password=request.POST['set-new-pass']
        new_confirm_password=request.POST['set-new-conpass']

        if new_password != new_confirm_password :
            messages.warning(request,"Password is not matching")
            return render(request,"auth/set-new-password.html",context)
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            user.set_password(new_password)
            user.save()
            messages.success(request,"Password Reset Success")
            return render(request,"auth/login.html")
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,"Something Went Wrong")
            return render(request,"auth/set-new-password.html",context)
        