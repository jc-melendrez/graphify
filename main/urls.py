from django.urls import path
from . import views
urlpatterns = [
    path('login/', views.login_page, name="login_page"),
    path('auth/google/', views.google_login, name='google_login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
]