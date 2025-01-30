from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.core.mail import send_mail, EmailMessage
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from .forms import CustomUserCreationForm, ClientRegistrationForm, LoginForm
from .models import CustomUser
from .decorators import client_required, employee_required
import random
from django.contrib.auth import get_user_model
from accounts.models import User
from projectname.settings import EMAIL_BACKEND
import jwt
from datetime import datetime
from django.conf import settings

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.role = 'client'
            user.save()
            messages.success(request, 'Registration successful. Please login.')
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                print(f"User role: {user.role}")
                if user.role == 'employee':
                    return redirect('employee_dashboard')
                else:
                    return redirect('client_dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})

@login_required
def client_dashboard(request):
    print(f"Accessing client dashboard. User role: {request.user.role}")
    if request.user.role != 'client':
        messages.error(request, 'Access Denied. Clients only.')
        return redirect('login')
    context = {
        'username': request.user.username,
        'role': request.user.role
    }
    return render(request, 'accounts/client_dashboard.html', context)

@login_required
def employee_dashboard(request):
    print(f"Accessing employee dashboard. User role: {request.user.role}")
    if request.user.role != 'employee':
        messages.error(request, 'Access Denied. Employees only.')
        return redirect('login')
    context = {
        'username': request.user.username,
        'role': request.user.role
    }
    return render(request, 'accounts/employee_dashboard.html', context)


def home(request):
    return render(request, 'accounts/home.html')


def forgot_password(request):
    token = request.GET.get('token')
    
    if request.method == 'POST':
        email = request.POST.get('email').strip()
        
        try:
            user = User.objects.filter(email__iexact=email).first()
            print(f"User found: {user}")
            
            if user:
                # Generate OTP
                otp = str(random.randint(100000, 999999))
                print(f"Generated OTP: {otp}")
                
                # Save OTP in session
                request.session['reset_otp'] = otp
                request.session['reset_email'] = user.email
                
                try:
                    # Render HTML email template
                    html_message = render_to_string('accounts/email/reset_password_otp.html', {
                        'otp': otp
                    })
                    
                    # Send email
                    email = EmailMessage(
                        'Password Reset OTP',
                        html_message,
                        settings.EMAIL_HOST_USER,
                        [user.email]
                    )
                    email.content_subtype = "html"  # Set content type to HTML
                    email.send(fail_silently=False)
                    
                    print(f"OTP {otp} has been sent to {email}")
                    messages.success(request, 'OTP has been sent to your email.')
                except Exception as email_error:
                    print(f"Email error: {str(email_error)}")
                    messages.warning(request, f'Email sending failed, but for testing, your OTP is: {otp}')
                
                return redirect('verify_otp')
            else:
                print(f"No user found for email: '{email}'")
                messages.error(request, 'No user found with this email address.')
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            messages.error(request, f'An error occurred: {str(e)}')
    
    # Handle JWT token if present
    if token:
        try:
            # Decode token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            request.session['reset_email'] = user.email
            return redirect('reset_password')
        except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
            messages.error(request, 'Invalid or expired reset link.')
    
    return render(request, 'accounts/forgot_password.html')

def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')
        stored_otp = request.session.get('reset_otp')
        if otp == stored_otp:
            return redirect('reset_password')
        else:
            messages.error(request, 'Invalid OTP')
    return render(request, 'accounts/verify_otp.html')

def reset_password(request):
    if request.method == 'POST':
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        email = request.session.get('reset_email')
        
        print(f"Debug - Email from session: {email}")
        
        if password1 != password2:
            messages.error(request, 'Passwords do not match')
            return render(request, 'accounts/reset_password.html')
            
        if not email:
            messages.error(request, 'Reset email not found in session')
            return render(request, 'accounts/reset_password.html')
            
        try:
            user = User.objects.filter(email=email).first()
            if user:
                user.set_password(password1)
                user.save()
                
                # Clear session
                request.session.pop('reset_otp', None)
                request.session.pop('reset_email', None)
                
                messages.success(request, 'Password has been reset successfully')
                return redirect('login')
            else:
                messages.error(request, 'User not found')
                print(f"User not found for email: {email}")  # Debug print
        except Exception as e:
            print(f"Password reset error: {str(e)}")  # Debug print
            messages.error(request, 'An error occurred while resetting password')
    
    return render(request, 'accounts/reset_password.html')