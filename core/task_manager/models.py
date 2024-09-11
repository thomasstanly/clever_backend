from datetime import date
from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin,BaseUserManager
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.
class Manager(BaseUserManager):
    def create_user(self,email,username,password, **other_field):
        if not email:
            raise ValueError('User Must Have An Email Adress')
        email = self.normalize_email(email)
        user = self.model(email=email,username=username,**other_field)
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self,email,username,password, **other_field):
        other_field.setdefault('is_active',True)
        other_field.setdefault('is_superuser',True)
        other_field.setdefault('is_staff',True)
        other_field.setdefault('is_email_verified',True)
        return self.create_user(email,username,password, **other_field)
 
class User(AbstractBaseUser,PermissionsMixin):
    username = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=30)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now_add=True)
    otp = models.IntegerField(null=True)
    otp_expire = models.DateTimeField(null=True)
    is_email_verified = models.BooleanField(default=False)


    objects = Manager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']


    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        refresh["is_superuser"] = self.is_superuser
        refresh["email"] = str(self.id)
        return {
            'refresh': str(refresh),
            'access': str((refresh.access_token))
        }


class TaskManager(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tasks')
    task_name = models.CharField(max_length=100)
    start_date = models.DateField(null=True)
    start_time = models.TimeField(null=True)
    end_date = models.DateField(null=True)
    end_time = models.TimeField(null=True)
    is_complete = models.BooleanField(default=False)


    def __str__(self):
        return self.task_name
    
    def save(self,*argss,**kwargs):
        if self.start_date < date.today():
            raise ValidationError('Enter a validate start date')
        elif self.start_date > self.end_date:
            raise ValidationError('Enter a validate starting date')
        elif self.start_date == self.end_date and self.start_time > self.end_time:
            raise ValidationError('Enter a validate starting time')
        else:
            super().save(*argss,**kwargs)

    class Meta:
        ordering = ['-start_date']