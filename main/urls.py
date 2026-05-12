from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views


# Create router and register viewset
router = DefaultRouter()
router.register(r'datasets', views.DatasetViewSet, basename='dataset')


# API URLs
urlpatterns = [
    path('', views.landing_page, name='landing_page'),
    path('dashboard/', views.dashie, name='dashie'),
    
    path('api/', include(router.urls)),
    # Additional custom endpoints
    path('api/datasets/<int:pk>/graph/', views.DatasetViewSet.as_view({'get': 'graph'}), name='dataset-graph'),
    path('api/parse-csv/', views.DatasetViewSet.as_view({'post': 'parse_csv'}), name='parse-csv'),
    path('api/stats/', views.DatasetViewSet.as_view({'get': 'stats'}), name='stats'),
]