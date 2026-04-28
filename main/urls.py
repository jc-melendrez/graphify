from django.urls import path
from main import views

urlpatterns = [
    path('', views.login_page, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('register/', views.register_view, name='register'),
    path('verify-otp/', views.otp_verify_view, name='verify_otp'),
    path('auth/google/', views.google_login, name='google_login'), # JS hits this
    path('auth/github/', views.github_login, name='github_login'),
    # path('auth/github/callback/', views.github_callback, name='github_callback'),
    path('logout/', views.logout_view, name='logout'),
]