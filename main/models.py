from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Password_Details(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    website_name = models.CharField(max_length=100)
    website_link = models.URLField(max_length=200, blank=True)
    website_username = models.CharField(max_length=100)
    website_password = models.CharField(max_length=1000)
    website_notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.website_name
