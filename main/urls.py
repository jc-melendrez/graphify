from django.urls import path
from django.views.generic import RedirectView
from . import views 

urlpatterns = [
    path('', views.landing_page, name = 'landing_page'),
    path('dashie/', views.dashie, name = 'dashie'),
]