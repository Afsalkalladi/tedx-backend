# filepath: /Users/afsalkalladi/Movies/tedx-backend/authentication/management/commands/create_admin.py
from django.core.management.base import BaseCommand
from authentication.models import User

class Command(BaseCommand):
    help = 'Creates an admin user'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str)
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)

    def handle(self, *args, **options):
        email = options['email']
        username = options['username']
        password = options['password']
        
        if User.objects.filter(email=email).exists():
            self.stdout.write(self.style.WARNING(f'User with email {email} already exists'))
            return
            
        user = User.objects.create_user(
            email=email,
            username=username,
            password=password,
            role=User.ADMIN,
            is_staff=True,
            is_superuser=True
        )
        
        self.stdout.write(self.style.SUCCESS(f'Admin user created: {email}'))