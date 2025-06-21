from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_google_user = models.BooleanField(default=False)
    google_id = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return self.email
    
    @property
    def user_type(self):
        """Returns simple user type"""
        if self.is_superuser:
            return 'superuser'
        elif self.is_staff:
            return 'staff'
        return 'user'