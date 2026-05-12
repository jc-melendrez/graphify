from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import DatasetViewSet


# Create router and register viewset
router = DefaultRouter()
router.register(r'datasets', DatasetViewSet, basename='dataset')


# API URLs
urlpatterns = [
    path('api/', include(router.urls)),
    # Additional custom endpoints
    path('api/datasets/<int:pk>/graph/', DatasetViewSet.as_view({'get': 'graph'}), name='dataset-graph'),
    path('api/parse-csv/', DatasetViewSet.as_view({'post': 'parse_csv'}), name='parse-csv'),
    path('api/stats/', DatasetViewSet.as_view({'get': 'stats'}), name='stats'),
]