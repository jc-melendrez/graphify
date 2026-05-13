from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views


# Create router and register viewset
router = DefaultRouter()
router.register(r'datasets', views.DatasetViewSet, basename='dataset')


# API URLs
urlpatterns = [
    # Frontend Pages
    path('', views.landing_page, name='landing_page'),
    path('dashie/', views.dashie, name='dashie'),
    
    # API Endpoints
    # Explicitly mapped paths go first to match documentation exactly
    path('api/parse-csv/', views.DatasetViewSet.as_view({'post': 'parse_csv'}), name='api-parse-csv'),
    path('api/stats/', views.DatasetViewSet.as_view({'get': 'stats'}), name='api-stats'),
    path('api/', include(router.urls)),
]