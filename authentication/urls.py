from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_page, name='login'),
    path('register/', views.register_view, name='register'),
    path('verify-otp/', views.otp_verify_view, name='verify_otp'),
    path('google/', views.google_login, name='google_login'),
    path('github/', views.github_login, name='github_login'),
    path('logout/', views.logout_view, name='logout'),
]