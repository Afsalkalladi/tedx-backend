from rest_framework import permissions

class IsSuperuser(permissions.BasePermission):
    """Permission for superuser only operations"""
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser

class IsStaffOrAbove(permissions.BasePermission):
    """Permission for staff and superuser operations"""
    
    def has_permission(self, request, view):
        return (request.user and request.user.is_authenticated and 
                (request.user.is_staff or request.user.is_superuser))