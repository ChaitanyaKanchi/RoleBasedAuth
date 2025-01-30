from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import EmailMessage
from django.conf import settings
import jwt
from datetime import datetime, timedelta
from .models import User
from django.template.loader import render_to_string

@receiver(post_save, sender=User)
def send_employee_welcome_email(sender, instance, created, **kwargs):
    print(f"\n=== Debug: Signal Triggered ===")
    print(f"Created: {created}")
    print(f"Role: {instance.role}")
    print(f"Email: {instance.email}")
    
    # Only send email if role is employee AND email is set
    if instance.role == 'employee' and instance.email:
        try:
            # Generate JWT token
            token = jwt.encode({
                'user_id': instance.id,
                'email': instance.email,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, settings.SECRET_KEY, algorithm='HS256')
            
            reset_link = f"http://127.0.0.1:8000/reset-password/?token={token}"
            
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
            print(f"Error: {str(e)}") 