from django.db import models
from django.contrib.auth.models import User

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target = models.CharField(max_length=255)
    result = models.TextField()
    scanned_at = models.DateTimeField(auto_now_add=True)
    scan_type = models.CharField(max_length=20)  # Novo polje za tip skeniranja
    
    def __str__(self):
        return f"{self.target} - {self.scan_type} at {self.scanned_at}"


class Scan(models.Model):
    target = models.CharField(max_length=255)
    scanned_at = models.DateTimeField(auto_now_add=True)
    # Dodaj status polje (primer enum-like polje)
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('done', 'Done'),
        ('failed', 'Failed'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    # Ostala polja...
