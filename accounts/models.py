from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail, EmailMessage
from django.urls import reverse
from django.conf import settings
from django.apps import apps
import jwt
from datetime import datetime, timedelta
from django.template.loader import render_to_string

class CustomUser(AbstractUser):
    is_client = models.BooleanField(default=False)
    is_employee = models.BooleanField(default=False)
    phone = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)

    # Add unique related_names to avoid conflicts
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        related_name='custom_user_set',
        help_text='The groups this user belongs to.',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        related_name='custom_user_set',
        help_text='Specific permissions for this user.',
    )

    def __str__(self):
        return self.username

class User(AbstractUser):
    ROLES = (
        ('client', 'Client'),
        ('employee', 'Employee'),
        ('admin', 'Admin'),
    )
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLES, default='client')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.username} - {self.role}"

    def save(self, *args, **kwargs):
        if self.is_superuser:
            self.role = 'admin'
        super().save(*args, **kwargs)

# Register the signal
def ready(self):
    User = apps.get_model('accounts', 'User')
    post_save.connect(send_employee_welcome_email, sender=User)

@receiver(post_save, sender=User)
def send_employee_welcome_email(sender, instance, created, **kwargs):
    # print(f"\n=== Debug: Signal Triggered ===")
    # print(f"Created: {created}")
    # print(f"Role: {instance.role}")
    # print(f"Email: {instance.email}")
    
    if created and instance.role == 'employee':
        try:
            # Generate JWT token
            token = jwt.encode({
                'user_id': instance.id,
                'email': instance.email,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, settings.SECRET_KEY, algorithm='HS256')
            
            reset_link = f"http://127.0.0.1:8000//?token={token}"
            
            # Render HTML email template
            html_message = render_to_string('accounts/email/employee_welcome.html', {
                'username': instance.username,
                'reset_link': reset_link,
            })
            
            # Send email
            email = EmailMessage(
                subject='Welcome to the Team - Set Your Password',
                body=html_message,
                from_email=settings.EMAIL_HOST_USER,
                to=[instance.email],
            )
            email.content_subtype = "html"  # Set content type to HTML
            email.send(fail_silently=False)
            print(f"Email sent successfully to {instance.email}!")
            
        except Exception as e:
            print(f"Error in send_employee_welcome_email: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")

