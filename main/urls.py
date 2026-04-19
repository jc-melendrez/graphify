from django.urls import path
from main import views

urlpatterns = [
    path('', views.login_page, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('auth/google/', views.google_login, name='google_login'), # JS hits this
    path('auth/github/', views.github_login, name='github_login'),
    path('auth/github/callback/', views.github_callback, name='github_callback'),
    path('logout/', views.logout_view, name='logout'),
]