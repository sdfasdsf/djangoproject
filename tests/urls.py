from django.urls import path
from . import views  # views.py에서 정의한 APIView 클래스들을 가져옵니다.

urlpatterns = [
    path('signup/', views.Signup.as_view(), name='signup'),  # 회원가입
    path('login/', views.Login.as_view(), name='login'),  # 로그인
    path('logout/', views.Logout.as_view(), name='logout'),  # 로그아웃
    path('check-login-status/', views.CheckLoginStatus.as_view(),name='check-login-status'), # 로그인 상태 확인
 
]
