from django.contrib import admin
from rest_framework_simplejwt.views  import TokenObtainPairView, TokenRefreshView
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from . import views

router = DefaultRouter()
router.register('task',views.TaskManger, basename='task_manager')

urlpatterns = [
    path('api/signup/', views.sign_up, name='sign_up' ),
    path('api/otp/',views.otp_verfication, name='otp'),
    path('api/login/',views.login, name='login'),
    path('api/otp_login/',views.otp_login, name='otp_login'),
    path('api/otp_authenticate/',views.otp_authenticate, name='otp_authenticate'),
    path('api/logout/',views.logout, name='logout'),
    path('api/',include(router.urls))
]
