"""
创建Multi-Tenant Auth超级用户
"""

from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError
from getpass import getpass

from ...services import AuthService
from ...exceptions import EmailAlreadyExistsError


class Command(BaseCommand):
    help = 'Create a Multi-Tenant Auth superuser'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Email address for the superuser'
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Password for the superuser'
        )
        parser.add_argument(
            '--name',
            type=str,
            help='Display name for the superuser'
        )

    def handle(self, *args, **options):
        """执行创建"""
        try:
            # 获取用户信息
            email = options.get('email')
            password = options.get('password')
            name = options.get('name')

            # 交互式输入
            if not email:
                email = input('Email: ').strip()

            if not password:
                password = getpass('Password: ')
                confirm_password = getpass('Confirm password: ')
                if password != confirm_password:
                    raise CommandError("Passwords do not match")

            if not name:
                name = input('Display name (optional): ').strip() or None

            if not email:
                raise CommandError("Email is required")

            if not password:
                raise CommandError("Password is required")

            # 验证邮箱格式
            from django.core.validators import validate_email
            try:
                validate_email(email)
            except ValidationError:
                raise CommandError("Invalid email format")

            # 创建用户
            self.stdout.write(f"🚀 Creating superuser: {email}")

            auth_service = AuthService()
            result = auth_service.register_user(
                email=email,
                password=password,
                personal_info={'name': name} if name else {}
            )

            if result.get('success'):
                user_data = result['user']
                self.stdout.write(self.style.SUCCESS('✅ Superuser created successfully!'))
                self.stdout.write(f"   ID: {user_data['id']}")
                self.stdout.write(f"   Email: {user_data['email']}")
                if user_data.get('display_name'):
                    self.stdout.write(f"   Name: {user_data['display_name']}")
                self.stdout.write(f"   Language: {user_data['language']}")
            else:
                raise CommandError("Failed to create superuser")

        except EmailAlreadyExistsError:
            self.stdout.write(
                self.style.ERROR(f'❌ User with email "{email}" already exists')
            )
        except ValidationError as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Validation error: {str(e)}')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Failed to create superuser: {str(e)}')
            )
            raise CommandError(f"Failed to create superuser: {str(e)}")