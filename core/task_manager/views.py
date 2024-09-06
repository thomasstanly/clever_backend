import random
from datetime import timedelta
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from rest_framework import status, viewsets
from django.core.mail import send_mail
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserRegisterSerializer, LoginSerializer, TaskSerializer
from .models import User, TaskManager

@api_view(['POST'])
def sign_up(request):
    if request.method == 'POST':
        serializer = UserRegisterSerializer(data=request.data)

        if serializer.is_valid():
            otp_value = random.randint(10000,99999)
            send_mail(
                'OTP verification from Clang Mount',
                f"{otp_value} is your OTP from Clang Mount to verify your email. This is a computer-generated email.",
                'clangmount@gmail.com',
                [request.data.get('email')],
                fail_silently=False
            )
            user = serializer.save()
            user.otp = otp_value
            user.otp_expire = timezone.now() + timedelta(seconds=20)
            user.save()

            return Response(
                {'email':user.email,'expiry':user.otp_expire,
                'message':f"OTP has sent to registred e-mail"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def otp_verfication(request):
    if request.method == 'POST':
        recived_otp = request.data.get('otpvalue')
       
        recived_email = request.data.get('email')
       
        user = User.objects.get(email=recived_email)

        if timezone.now() - user.otp_expire > timedelta(seconds=20):
            return Response({'message':'time expire'},status=status.HTTP_400_BAD_REQUEST)
        
        if recived_otp == str(user.otp):
            user.is_email_verified = True
            user.is_active = True
            user.save()
                
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

        return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['POST'])
def login(request):
    if request.method == 'POST':
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def otp_login(request):
    if request.method == 'POST':
        email = request.data.get('otp_email')
        
    
    try:
        user = User.objects.get(email=email)
        otp_value = random.randint(10000,99999)
        user.otp = otp_value
        user.otp_expire = timezone.now() + timedelta(seconds=20)
        user.save()
    except User.DoesNotExist:
        return Response({'message':'Invalid email id'},status=status.HTTP_400_BAD_REQUEST)
    
    send_mail(
        'OTP verification from Clang Mount',
        f"{otp_value} is your OTP from Clang Mount to verify your email. This is a computer-generated email.",
        'clangmount@gmail.com',
        [email],
        fail_silently=False
    )

    return Response({'message': 'OTP mailed','otp':otp_value}, status=status.HTTP_200_OK)


@api_view(['POST'])
def otp_authenticate(request):
    if request.method == 'POST':
        otp = request.data.get('otp')
        email = request.data.get('otp_email')
        print(email)
        user = User.objects.get(email=email)

        if timezone.now() - user.otp_expire > timedelta(seconds=20):
            return Response({'message':'time expire'},status=status.HTTP_400_BAD_REQUEST)
        
        
        
        if otp == str(user.otp):
            user.is_email_verified = True
            user.is_active = True
            user.save()
            token = user.tokens()

            return Response({
                'email': user.email,
                'access_token': token['access'],
                'refresh_token': token['refresh'],
                'isAdmin': user.is_superuser
            }, status=status.HTTP_200_OK)

        return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def logout(request):
    
    try:
        refresh_token = request.data["refresh_token"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        content = {'message': 'Successfully logged out'}
        return Response(status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        content = {'message': 'refresh token invalid'}
        return Response(content,status=status.HTTP_400_BAD_REQUEST)

# CRUD operation for 
class TaskManger(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        query = TaskManager.objects.filter(user=request.user)
        serializer = TaskSerializer(query, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save(user=request.user)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except ValidationError as error:
                return Response(error.message, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        
        query = get_object_or_404(TaskManager, pk=pk)
        serializer = TaskSerializer(query)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def update(self, request, pk=None):
        
        query = get_object_or_404(TaskManager, pk=pk)
        serializer = TaskSerializer(query, data=request.data)
        if serializer.is_valid():
            try:
                serializer.save(user=request.user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except ValidationError as error:
                return Response(error.message, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        
        query = get_object_or_404(TaskManager, pk=pk)
        serializer = TaskSerializer(query, data=request.data, partial=True)
        if serializer.is_valid():
            try:
                serializer.save(user=request.user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except ValidationError as error:
                return Response(error.message, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        
        task = get_object_or_404(TaskManager, pk=pk)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    