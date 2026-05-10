from django.urls import path
from django.views.generic import RedirectView
from . import views

urlpatterns = [
    # Automatically redirect the root URL to the login page
    path('', RedirectView.as_view(pattern_name='login', permanent=False), name='home_redirect'),
    
    path('dashboard/', views.dashboard_view, name='dashboard'),
]