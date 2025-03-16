import pytest
from rest_framework import status
from django.urls import reverse
from rest_framework.test import APIClient

@pytest.mark.django_db  # 데이터베이스를 사용하는 테스트라는 것을 명시
def test_signup_valid_data():
    # API 요청에 사용할 URL
    url = reverse('signup')  # URL 패턴 이름에 맞게 수정

    # 테스트 데이터
    data = {
        "username": "testuser4",
        "password": "password1234",
        "password2": "password1234",  # 비밀번호 확인
        "nickname": "testnickname4"
    }

    # 클라이언트 객체 생성
    client = APIClient()

    # POST 요청 보내기
    response = client.post(url, data, format='json')

    # 응답 상태 코드가 201 (Created)인지 확인
    assert response.status_code == status.HTTP_201_CREATED

    # 응답 내용 확인 (필요시 추가적인 assert 작성 가능)
    assert 'username' in response.data
    assert 'nickname' in response.data
    assert response.data['username'] == data['username']
    assert response.data['nickname'] == data['nickname']


@pytest.mark.django_db
def test_signup_invalid_data():
    # 유효하지 않은 데이터로 테스트
    url = reverse('signup')

    data = {
        "username": "",  # 빈 아이디
        "password": "123",  # 너무 짧은 비밀번호
        "password2": "123",  # 비밀번호 확인
        "nickname": "testnickname"
    }

    client = APIClient()

    response = client.post(url, data, format='json')

    # 응답 상태 코드가 400 (Bad Request)인지 확인
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    # 에러 메시지가 있는지 확인
    assert 'errors' in response.data
    assert 'username' in response.data['errors']
    assert 'password' in response.data['errors']
