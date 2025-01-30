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
from datetime import datetime, timedelta
from django.conf import settings
from django.urls import reverse
import re

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


def generate_reset_token(email):
    """Generate JWT token for password reset"""
    exp_time = datetime.utcnow() + timedelta(minutes=30)
    return jwt.encode(
        {'email': email, 'exp': exp_time},
        settings.SECRET_KEY,
        algorithm='HS256'
    )

def verify_reset_token(token):
    """Verify JWT token validity"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email').strip()
        
        try:
            user = User.objects.filter(email__iexact=email).first()
            if user:
                # Generate reset token
                token = generate_reset_token(email)
                reset_link = request.build_absolute_uri(
                    f"{reverse('reset_password')}?token={token}"
                )
                
                # Send reset email
                html_message = render_to_string('accounts/email/reset_password_email.html', {
                    'reset_link': reset_link
                })
                
                email = EmailMessage(
                    'Password Reset Instructions',
                    html_message,
                    settings.EMAIL_HOST_USER,
                    [user.email]
                )
                email.content_subtype = "html"
                email.send(fail_silently=False)
                
                messages.success(request, 'Password reset instructions have been sent to your email.')
                return redirect('login')
            
            messages.error(request, 'No account found with this email address.')
            
        except Exception as e:
            messages.error(request, 'An error occurred. Please try again.')
            
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
    token = request.GET.get('token')
    email = verify_reset_token(token)
    
    if not email:
        messages.error(request, 'Invalid or expired reset link. Please request a new one.')
        return redirect('forgot_password')
    
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'accounts/reset_password.html', {'token': token})
            
        if not validate_password(password):
            messages.error(request, 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.')
            return render(request, 'accounts/reset_password.html', {'token': token})
            
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password has been reset successfully. Please login with your new password.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('forgot_password')
            
    return render(request, 'accounts/reset_password.html', {'token': token})

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True