from rest_framework import serializers
from .models import Dataset
import pandas as pd


class DatasetSerializer(serializers.ModelSerializer):
    """Serializer for Dataset model"""
    
    class Meta:
        model = Dataset
        fields = ['id', 'name', 'file', 'file_type', 'created_at', 'rows_count']
        read_only_fields = ['id', 'file_type', 'created_at', 'rows_count']
    
    def validate_file(self, value):
        """Validate uploaded file"""
        if not value:
            raise serializers.ValidationError("No file uploaded")
        
        # Check file extension
        file_name = value.name.lower()
        if not (file_name.endswith('.csv') or file_name.endswith('.xlsx') or file_name.endswith('.xls')):
            raise serializers.ValidationError("Only CSV and Excel files are allowed")
        
        return value


class GraphDataSerializer(serializers.Serializer):
    """Serializer for chart-ready data"""
    dataset_id = serializers.IntegerField()
    dataset_name = serializers.CharField()
    columns = serializers.ListField(child=serializers.CharField())
    data = serializers.ListField(child=serializers.DictField())
    chart_type = serializers.ChoiceField(
        choices=['line', 'bar', 'pie', 'scatter', 'area'],
        default='line'
    )
    title = serializers.CharField(default='Chart Data')
    
    def validate(self, data):
        """Validate chart data structure"""
        if not data.get('columns'):
            raise serializers.ValidationError("Columns are required")
        if not data.get('data'):
            raise serializers.ValidationError("Data is required")
        return data


class CSVParser(serializers.Serializer):
    """Serializer for CSV parsing"""
    file = serializers.FileField(required=True)
    delimiter = serializers.CharField(default=',', required=False)
    header_row = serializers.IntegerField(default=0, required=False)
    
    def validate_file(self, value):
        """Validate uploaded CSV file"""
        file_name = value.name.lower()
        if not file_name.endswith('.csv'):
            raise serializers.ValidationError("Only CSV files are allowed")
        return value
    
    def parse(self):
        """Parse CSV file and return structured data"""
        delimiter = self.validated_data.get('delimiter', ',')
        header_row = self.validated_data.get('header_row', 0)
        
        try:
            df = pd.read_csv(self.validated_data['file'], delimiter=delimiter, header=header_row)
            
            # Convert to JSON-serializable format
            result = {
                'columns': df.columns.tolist(),
                'data': df.to_dict('records'),
                'total_rows': len(df),
                'total_columns': len(df.columns)
            }
            
            return result
        except Exception as e:
            raise serializers.ValidationError(f"Error parsing CSV: {str(e)}")