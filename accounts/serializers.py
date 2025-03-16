from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    nickname = serializers.CharField(max_length=100)  # 닉네임 필드 추가

    class Meta:
        model = User
        fields = (
            "username",  # 아이디 필드
            "password",  # 비밀번호 필드
            "password2",  # 비밀번호 확인 필드
            "nickname"  # 닉네임 필드
        )

    def validate(self, data):
        # 비밀번호 일치 여부 확인
        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password": "비밀번호가 일치하지 않습니다."})

        # 비밀번호 강도 체크
        try:
            validate_password(data['password'])
        except Exception as e:
            raise serializers.ValidationError({"password": list(e.messages)})

        # 닉네임 중복 확인
        if User.objects.filter(nickname=data["nickname"]).exists():
            raise serializers.ValidationError({"nickname": "이 닉네임은 이미 사용 중입니다."})

        return data

    def create(self, validated_data):
        validated_data.pop("password2")  # password2 필드는 사용하지 않음
        return User.objects.create_user(**validated_data)
