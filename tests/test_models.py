from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models

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
class TestUser(AbstractUser):
    nickname = models.CharField('닉네임', max_length=150, unique=True)  # unique 설정을 추가하여 중복되지 않도록 함

    # groups와 user_permissions 필드의 related_name을 수정하여 충돌을 방지
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='accounts_user_set',  # 'auth.User.groups'와의 충돌을 방지
        blank=True
    )

    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='accounts_user_permissions_set',  # 'auth.User.user_permissions'와의 충돌을 방지
        blank=True
    )

    # CustomUserManager를 사용하도록 설정
    objects = CustomUserManager()
    
    class Meta:
        app_label = 'accounts'  # 'accounts' 앱에 속한다고 명시적으로 지정


    def __str__(self):
        return self.username
