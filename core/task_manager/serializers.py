from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from .models import User, TaskManager

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=30, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=30, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email','password', 'password2', 'username']

    def validate(self,attrs):
        password = attrs.get('password','')
        password2 = attrs.get('password2','')
        email =  attrs.get('email','')
        username =  attrs.get('username','')
        if password != password2:
            raise serializers.ValidationError('password dosn\'t match')
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Email is already registered.')
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError('Email is already registered.')
        return attrs
    
    def create(self,validated_data):

        validated_data.pop('password2')

        user = User.objects.create_user(
            email = validated_data['email'],
            password = validated_data.get('password'),
            username = validated_data.get('username')
            )
        return user

class LoginSerializer(serializers.ModelSerializer):
    email= serializers.EmailField(max_length=50)
    password = serializers.CharField(max_length=50, write_only=True)
    access_token= serializers.CharField(max_length=500, read_only=True)
    refresh_token= serializers.CharField(max_length=500, read_only=True)
    isAdmin = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = ['email','password','access_token','refresh_token','isAdmin']

    def validate(self,attrs):
        email= attrs.get('email')
        password= attrs.get('password')
        request = self.context.get('request')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise AuthenticationFailed('Invalid Username, try again')


        if not user.check_password(password):
            raise AuthenticationFailed('Invalid password, try again')
        
        token=user.tokens()
        
        return {
            'email':user.email,
            'isAdmin':user.is_superuser,
            'access_token':str(token.get('access')),
            'refresh_token':str(token.get('refresh')),
        }

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskManager
        fields = '__all__'
        extra_kwargs = {
            'user': {'read_only': True},
        }

