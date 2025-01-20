from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class ClientRegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'phone_number', 'address']
        
    def save(self, commit=True):
        user = super().save(commit=False)
        user.role = 'CLIENT'
        if commit:
            user.save()
        return user

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'password1', 'password2')  # Only basic fields for clients 