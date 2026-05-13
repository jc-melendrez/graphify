from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from .models import Dataset
from .serializers import DatasetSerializer, GraphDataSerializer, CSVParser
import pandas as pd
import os

def landing_page(request):
    """View to render the landing page."""
    return render(request, 'main/landing_page.html')

@login_required
def dashie(request):
    """View to render the main dashboard (requires login)."""
    return render(request, 'main/dashie.html')


class DatasetViewSet(viewsets.ModelViewSet):
    """ViewSet for Dataset CRUD operations"""
    queryset = Dataset.objects.none()  # Safety default
    serializer_class = DatasetSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    
    def get_queryset(self):
        """Get datasets owned by the current user"""
        return Dataset.objects.filter(user=self.request.user).order_by('-created_at')
    
    def perform_create(self, serializer):
        """Create a new dataset associated with the current user"""
        serializer.save(user=self.request.user)
    
    @action(detail=True, methods=['get'], url_path='graph')
    def graph(self, request, pk=None):
        """Get chart-ready data for a specific dataset"""
        try:
            dataset = self.get_object()
            
            # Parse the file based on type
            if dataset.file_type == 'csv':
                df = pd.read_csv(dataset.file)
            else:
                df = pd.read_excel(dataset.file)
            
            # Convert to Google Charts format
            chart_data = {
                'dataset_id': dataset.id,
                'dataset_name': dataset.name,
                'columns': df.columns.tolist(),
                'data': df.to_dict('records'),
                'chart_type': 'line',
                'title': dataset.name,
                'total_rows': len(df),
                'total_columns': len(df.columns)
            }
            
            return Response(chart_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response(
                {'error': f'Error processing dataset: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='parse-csv')
    def parse_csv(self, request):
        """Parse uploaded CSV file and return structured data"""
        try:
            # Use CSVParser serializer
            parser = CSVParser(data=request.data)
            if not parser.is_valid():
                return Response(parser.errors, status=status.HTTP_400_BAD_REQUEST)
            
            # Parse the CSV
            result = parser.parse()
            
            return Response(result, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response(
                {'error': f'Error parsing CSV: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='stats')
    def stats(self, request):
        """Get statistics about the current user's datasets"""
        queryset = self.get_queryset()
        total_datasets = queryset.count()
        total_rows = queryset.aggregate(
            total_rows=Sum('rows_count')
        )['total_rows'] or 0
        
        return Response({
            'total_datasets': total_datasets,
            'total_rows': total_rows
        }, status=status.HTTP_200_OK)
