# accounts/tests/test_views.py
import pytest
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken


@pytest.mark.django_db
def test_signup_valid_data(client):
    url = reverse('signup')  # URL 패턴에 맞게 수정하세요
    data = {
        "username": "testuser",
        "password": "password123",
        "nickname": "testnickname"
    }
    response = client.post(url, data, format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert "username" in response.data
    assert "nickname" in response.data


@pytest.mark.django_db
def test_signup_invalid_data(client):
    url = reverse('signup')  # URL 패턴에 맞게 수정하세요
    data = {
        "username": "",  # username이 비어 있으면 안 됨
        "password": "password123",
        "nickname": "testnickname"
    }
    response = client.post(url, data, format='json')
    
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "errors" in response.data


@pytest.mark.django_db
def test_login_valid_credentials(client):
    # 사용자 생성
    user = User.objects.create_user(username='testuser', password='password123')
    url = reverse('login')  # URL 패턴에 맞게 수정하세요
    data = {
        "username": "testuser",
        "password": "password123"
    }
    response = client.post(url, data, format='json')
    
    assert response.status_code == status.HTTP_200_OK
    assert "token" in response.data  # JWT 토큰이 반환되어야 함


@pytest.mark.django_db
def test_login_invalid_credentials(client):
    url = reverse('login')  # URL 패턴에 맞게 수정하세요
    data = {
        "username": "wronguser",
        "password": "wrongpassword"
    }
    response = client.post(url, data, format='json')
    
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "error" in response.data  # "아이디 또는 비밀번호가 올바르지 않습니다."라는 에러가 반환되어야 함


@pytest.mark.django_db
def test_logout_authenticated_user(client):
    # 로그인된 상태에서 로그아웃 테스트
    user = User.objects.create_user(username='testuser', password='password123')
    client.login(username='testuser', password='password123')
    url = reverse('logout')  # URL 패턴에 맞게 수정하세요
    response = client.post(url)
    
    assert response.status_code == status.HTTP_302_FOUND  # 리디렉션이 발생해야 함
    assert 'refresh_token' not in response.cookies  # refresh_token 쿠키가 삭제되어야 함


@pytest.mark.django_db
def test_check_login_status_authenticated(client):
    # 로그인된 상태에서 로그인 상태 확인 API 테스트
    user = User.objects.create_user(username='testuser', password='password123')
    client.login(username='testuser', password='password123')
    url = reverse('check-login-status')  # URL 패턴에 맞게 수정하세요
    response = client.get(url)
    
    assert response.status_code == status.HTTP_200_OK
    assert response.data["message"] == "로그인 상태입니다."
    assert response.data["user"] == "testuser"


@pytest.mark.django_db
def test_check_login_status_not_authenticated(client):
    # 로그인되지 않은 상태에서 로그인 상태 확인 API 테스트
    url = reverse('check-login-status')  # URL 패턴에 맞게 수정하세요
    response = client.get(url)
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data["error"] == "로그인이 필요합니다."
