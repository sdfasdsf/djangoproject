# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken ,AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.contrib.auth import authenticate, login, logout , get_user_model
from django.http import JsonResponse
from django.shortcuts import redirect
from .serializers import SignupSerializer ,LoginSerializer # 회원가입을 위한 Serializer
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
                
                     # ⚠️ 유효성 검사 실패 시 에러 분석 후 일관된 에러 포맷 반환
            errors = serializer.errors

            if 'username' in errors:
                return Response({
                "error": {
                    "code": "USER_ALREADY_EXISTS",
                    "message": "이미 가입된 사용자입니다."
                }
                }, status=400)

            if 'nickname' in errors:
                return Response({
                    "error": {
                        "code": "NICKNAME_ALREADY_EXISTS",
                        "message": "이 닉네임은 이미 사용 중입니다."
                    }
            }, status=400)

        # 기타 다른 유효성 오류
            return Response({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "입력값이 유효하지 않습니다.",
                    "details": errors
                }
            }, status=400)

        except ValueError as ve:
            logger.error(f"회원가입 오류: {str(ve)}")
            return Response({
                'error': {'code': 'USER_CREATION_FAILED', 'message': str(ve)}
            }, status=500)

        except Exception as e:
            error_message = traceback.format_exc()
            logger.error(f"회원가입 중 오류 발생: {error_message}")
            return Response({
                'error': {
                    'code': 'SERVER_ERROR',
                    'message': '회원가입 처리 중 서버 오류가 발생했습니다.'
                }
            }, status=500)



class Login(APIView):
    permission_classes = [AllowAny]  # 인증이 필요하지 않음
    throttle_classes = [AnonRateThrottle]  # Rate limiting 적용

    def post(self, request):
        """
        로그인 처리
        - 아이디(username) 및 비밀번호로 사용자 인증
        - JWT 토큰 생성
        """
        # Serializer를 통해 요청 데이터 유효성 검증
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return JsonResponse({"error": "잘못된 요청입니다.", "details": serializer.errors}, status=400)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        # 사용자 인증
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # JWT 토큰 생성
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # 로그인 성공 시 토큰 반환
            return JsonResponse({"token": access_token}, status=200)
        else:
            # 로그인 실패 시 오류 메시지 반환
            return JsonResponse({
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "아이디 또는 비밀번호가 올바르지 않습니다."
                }
            }, status=400)


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
        
        
        
class CheckAuth(APIView):
    permission_classes = []

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({
                "error": {
                    "code": "TOKEN_NOT_FOUND",
                    "message": "토큰이 없습니다."
                }
            }, status=400)

        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']

            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User.objects.get(id=user_id)

            return Response({
                "message": "유효한 토큰입니다.",
                "user": {
                    "username": user.username,
                    "nickname": user.nickname
                }
            }, status=200)

        except InvalidToken:
            return Response({
                "error": {
                    "code": "INVALID_TOKEN",
                    "message": "토큰이 유효하지 않습니다."
                }
            }, status=400)

        except TokenError as e:
            if "Token is expired" in str(e):
                return Response({
                    "error": {
                        "code": "TOKEN_EXPIRED",
                        "message": "토큰이 만료되었습니다."
                    }
                }, status=400)
            else:
                return Response({
                    "error": {
                        "code": "INVALID_TOKEN",
                        "message": "토큰이 유효하지 않습니다."
                    }
                }, status=400)