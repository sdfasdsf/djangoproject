from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone

# 사용자 관리자
class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("아이디는 필수입니다")
        if not password or password.strip() == "":
            raise ValueError("비밀번호는 필수입니다.")
        
        username = self.normalize_username(username)  # 사용자 이름 정규화
        user = self.model(username=username, **extra_fields)  # User 모델 인스턴스 생성
        user.set_password(password)  # 비밀번호 해싱
        user.save(using=self._db)  # DB에 저장
        return user
    
    def normalize_username(self, username):
        """사용자 이름을 정규화하는 방법"""
        return username.strip().lower()  # 예: 소문자화 및 공백 제거


# 사용자 모델
class User(AbstractUser):
    nickname = models.CharField('닉네임', max_length=150, unique=True)  # unique 설정을 추가하여 중복되지 않도록 함

    # CustomUserManager를 사용하도록 설정
    objects = CustomUserManager()

    def __str__(self):
        return self.username


# JWT 토큰을 저장하는 모델
class UserToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # 사용자와 1:1 관계
    token = models.CharField(max_length=255)  # JWT 토큰 저장
    created_at = models.DateTimeField(auto_now_add=True)  # 토큰 생성 시간
    expired_at = models.DateTimeField()  # 토큰 만료 시간

    def __str__(self):
        return f"Token for {self.user.username}"

    def is_expired(self) -> bool:
        """토큰이 만료되었는지 확인하는 메소드"""
        return timezone.now() > self.expired_at
