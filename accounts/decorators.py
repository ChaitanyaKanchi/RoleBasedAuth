from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def client_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.role != 'CLIENT':
            messages.error(request, 'Access denied. Clients only.')
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def employee_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.role != 'EMPLOYEE':
            messages.error(request, 'Access denied. Employees only.')
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper 