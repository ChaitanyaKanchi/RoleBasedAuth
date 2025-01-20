from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('client/dashboard/', views.client_dashboard, name='client_dashboard'),
    path('employee/dashboard/', views.employee_dashboard, name='employee_dashboard'),
] 