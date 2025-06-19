from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    # Role constants for better code readability and consistency
    USER = 'user'
    ADMIN = 'admin'
    
    ROLE_CHOICES = [
        (USER, 'User'),
        (ADMIN, 'Admin'),
    ]
    
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default=USER)
    is_google_user = models.BooleanField(default=False)
    google_id = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return self.email
    
    @property
    def is_admin(self):
        """Convenient property to check if user is an admin"""
        return self.role == self.ADMIN