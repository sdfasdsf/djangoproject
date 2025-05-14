from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    nickname = serializers.CharField(max_length=100)  # 닉네임 필드

    class Meta:
        model = User
        fields = (
            "username",   # 아이디
            "password",   # 비밀번호
            "nickname"    # 닉네임
        )

    def validate(self, data):
        # 닉네임 중복 확인
        if User.objects.filter(nickname=data["nickname"]).exists():
            raise serializers.ValidationError({
                "nickname": "이 닉네임은 이미 사용 중입니다."
            })

        # 사용자 이름 중복 확인
        if User.objects.filter(username=data["username"]).exists():
            raise serializers.ValidationError({
                "username": "이미 가입된 사용자입니다."
            })

        return data

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            nickname=validated_data['nickname']
        )
