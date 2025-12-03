"""
用户模型
"""

import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import make_password, check_password

from .base import AuthBaseModel


class CustomUserManager(BaseUserManager):
    """自定义用户管理器"""

    def create_user(self, email, password=None, **extra_fields):
        """创建普通用户"""
        if not email:
            raise ValueError('Email is required')

        user = self.model(
            email=email.lower(),
            **extra_fields
        )
        if password:
            user.password_hash = make_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """创建超级用户"""
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('personal_info', {})
        return self.create_user(email, password, **extra_fields)


class User(AuthBaseModel, AbstractBaseUser):
    """用户模型"""

    email = models.EmailField(
        max_length=255,
        unique=True,
        db_index=True
    )
    password_hash = models.CharField(
        max_length=255
    )
    personal_info = models.JSONField(
        default=dict,
        help_text="用户个人信息 {name: string, avatar_url: string}"
    )
    settings = models.JSONField(
        default=dict,
        help_text="用户设置 {email_notifications: boolean, language: string}"
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True
    )
    last_login_at = models.DateTimeField(
        null=True,
        blank=True
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = '"multi_tenant_auth"."user"'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.email

    def set_password(self, password):
        """设置密码"""
        self.password_hash = make_password(password)
        self.save(update_fields=['password_hash'])

    def check_password(self, password):
        """验证密码"""
        return check_password(password, self.password_hash)

    @property
    def is_anonymous(self):
        """是否匿名用户"""
        return False

    @property
    def is_authenticated(self):
        """已认证"""
        return True

    @property
    def display_name(self):
        """显示名称"""
        return self.personal_info.get('name') or self.email

    @property
    def avatar_url(self):
        """头像URL"""
        return self.personal_info.get('avatar_url', '')

    @property
    def language(self):
        """用户语言"""
        return self.settings.get('language', 'en')

    @property
    def email_notifications_enabled(self):
        """是否启用邮件通知"""
        return self.settings.get('email_notifications', True)