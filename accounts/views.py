from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from .forms import CustomUserCreationForm, ClientRegistrationForm, LoginForm
from .decorators import client_required, employee_required

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
    if request.user.role != 'employee':
        messages.error(request, 'Access Denied. Employees only.')
        return redirect('login')
    return render(request, 'accounts/employee_dashboard.html')

def home(request):
    return render(request, 'accounts/home.html') 