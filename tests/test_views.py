# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.shortcuts import redirect
from accounts.serializers import SignupSerializer  # 회원가입을 위한 Serializer
import logging
import traceback

logger = logging.getLogger(__name__)

# 회원가입 처리 API
class Signup(APIView):
    permission_classes = [AllowAny]  # 인증이 필요하지 않음
    throttle_classes = [AnonRateThrottle]  # Rate limiting 적용

    def get(self, request):
        """회원가입 폼 표시"""
        return Response({'message': '회원가입 페이지입니다.'})

    def post(self, request):
        """
        회원가입 처리
        - 데이터 유효성 검사
        - 에러 처리
        - 회원가입 성공/실패 처리
        """
        try:
            serializer = SignupSerializer(data=request.data)
            if serializer.is_valid():
                # 사용자 생성
                user = serializer.save()

                if not user:
                    raise ValueError('사용자 생성에 실패했습니다.')  # 사용자 생성 실패 시 예외 처리

                # 성공 메시지
                return Response({
                    'username': user.username,
                    'nickname': user.nickname,
                    'password': user.password,
                })

            # 유효성 검사 실패 시 에러 메시지 표시
            return Response({
                'message': '회원가입 페이지입니다.',
                'errors': serializer.errors
            }, status=400)

        except ValueError as ve:
            # 사용자 생성 실패 시 처리
            logger.error(f"회원가입 오류: {str(ve)}")
            return Response({
                'error': {'code': 'USER_CREATION_FAILED', 'message': str(ve)}
            }, status=500)

        except Exception as e:
            # 예외 발생 시 로깅 및 에러 메시지
            error_message = traceback.format_exc()  # 예외의 스택 트레이스를 문자열로 가져옴
            logger.error(f"회원가입 중 오류 발생: {error_message}")  # 오류 메시지 로깅
            return Response({
                'message': '회원가입 처리 중 오류가 발생했습니다.',
                'errors': {'server': ['서버 오류가 발생했습니다.']},
            }, status=500)


# 로그인 처리 API
class Login(APIView):
    permission_classes = [AllowAny]  # 인증이 필요하지 않음
    throttle_classes = [AnonRateThrottle]  # Rate limiting 적용

    def post(self, request):
        """
        로그인 처리
        - 아이디(username) 및 비밀번호로 사용자 인증
        - JWT 토큰 생성
        """
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return JsonResponse({"error": "아이디와 비밀번호를 입력해 주세요."}, status=400)

        # 사용자 인증
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # JWT 토큰 생성
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return JsonResponse({"token": access_token}, status=200)
        else:
            return JsonResponse({"error": "아이디 또는 비밀번호가 올바르지 않습니다."}, status=400)


# 로그아웃 처리 API
class Logout(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]  # 로그인된 사용자만 로그아웃 가능

    def post(self, request):
        """로그아웃 처리"""
        try:
            # refresh token을 가져옵니다.
            refresh_token = request.COOKIES.get("refresh_token")

            if not refresh_token:
                return JsonResponse({"error": "로그아웃 실패, refresh token이 없습니다."}, status=400)

            # refresh token을 사용하여 토큰을 블랙리스트 처리
            token = RefreshToken(refresh_token)
            token.blacklist()  # 토큰을 블랙리스트에 추가하여 더 이상 사용할 수 없도록 처리

            # 로그아웃 처리
            logout(request)

            # 쿠키 삭제
            response = redirect('/')
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')

            return response

        except Exception as e:
            logger.error(f"로그아웃 실패: {str(e)}")
            return Response({"error": "로그아웃 실패", "details": str(e)}, status=400)


# 로그인 상태 확인 API
class CheckLoginStatus(APIView):
    permission_classes = [IsAuthenticated]  # 로그인된 사용자만 접근 가능

    def get(self, request):
        """
        로그인 여부 확인 API
        - 로그인된 사용자: 상태 200과 사용자 정보 반환
        - 로그인되지 않은 사용자: 상태 401 반환
        """
        if request.user.is_authenticated:
            return Response({
                "message": "로그인 상태입니다.",
                "user": request.user.username
            }, status=200)
        return Response({
            "error": "로그인이 필요합니다."
        }, status=401)
