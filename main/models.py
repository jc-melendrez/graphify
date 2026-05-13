from django.db import models
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
from django.conf import settings
import os
import pandas as pd


class DatasetStorage(FileSystemStorage):
    """Custom storage for uploaded files"""
    
    def get_available_name(self, name, max_length=None):
        """Generate unique filename if file exists"""
        if self.exists(name):
            name = name.rsplit('.', 1)[0] + '_' + str(os.urandom(4).hex()) + '.' + name.rsplit('.', 1)[1]
        return name


class Dataset(models.Model):
    """Model to store uploaded dataset files"""
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='datasets',
        help_text="User who owns this dataset"
    )
    name = models.CharField(max_length=255, help_text="Dataset name")
    file = models.FileField(
        upload_to='datasets/',
        storage=DatasetStorage(),
        help_text="Uploaded file (CSV or Excel)"
    )
    file_type = models.CharField(
        max_length=10,
        choices=[('csv', 'CSV'), ('excel', 'Excel')],
        help_text="Type of uploaded file"
    )
    created_at = models.DateTimeField(auto_now_add=True, help_text="Date and time when dataset was created")
    rows_count = models.IntegerField(default=0, help_text="Number of rows in the dataset")
    
    class Meta:
        db_table = 'dataset'
        ordering = ['-created_at']
        verbose_name = 'Dataset'
        verbose_name_plural = 'Datasets'
    
    def __str__(self):
        return f"{self.name} ({self.file_type}) - {self.rows_count} rows"
    
    def save(self, *args, **kwargs):
        """Save the model and count rows safely"""
        is_new = self.pk is None
        
        # If it's a new upload, count rows before the first save if the file is available
        if is_new and self.file and self.file_type in ['csv', 'excel']:
            try:
                self.rows_count = self._count_rows()
            except Exception:
                self.rows_count = 0
                
        super().save(*args, **kwargs)
        
    def _count_rows(self):
        """Count rows in the uploaded file"""
        if self.file_type == 'csv':
            df = pd.read_csv(self.file)
        elif self.file_type == 'excel':
            df = pd.read_excel(self.file)
        else:
            return 0
        return len(df)
    
    def get_file_path(self):
        """Get the file path relative to media directory"""
        if self.file:
            return os.path.relpath(self.file.path, settings.MEDIA_ROOT)
        return None