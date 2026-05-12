from django.db import models
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
import os


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

        # first save file to disk
        is_new = self.pk is None
        super().save(*args, **kwargs)

        # only calculate once after initial save
        if is_new and self.file and self.file_type in ['csv', 'excel']:
            self.rows_count = self._count_rows()
            Dataset.objects.filter(pk=self.pk).update(rows_count=self.rows_count)
        
    def _count_rows(self):
        """Count rows in the uploaded file"""
        try:
            if self.file_type == 'csv':
                import pandas as pd
                df = pd.read_csv(self.file)
                return len(df)
            elif self.file_type == 'excel':
                import pandas as pd
                df = pd.read_excel(self.file)
                return len(df)
            return 0
        except Exception:
            return 0
    
    def get_file_path(self):
        """Get the file path relative to media directory"""
        if self.file:
            return os.path.relpath(self.file.path, os.path.join(os.path.dirname(__file__), '..', 'media'))
        return None