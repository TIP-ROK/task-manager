import logging

from django.contrib.auth import get_user_model
from rest_framework import serializers

from auth_app.models import ConfirmationCode

logger = logging.getLogger(__name__)
User = get_user_model()

class EmailConfirmationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, required=True)
    code = serializers.CharField(max_length=6, required=True)

    def validate(self, data):
        username = data.get('username')
        code = data.get('code')

        if not isinstance(username, str):
            raise TypeError("Expected a string value for username")
        if not isinstance(code, str):
            raise TypeError("Expected a string value for code")

        # Проверяем, существует ли пользователь
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError("Пользователь с таким именем не найден.")

        # Проверяем код подтверждения
        confirmation = ConfirmationCode.objects.filter(user=user, code=code, is_confirmed=False).first()
        if not confirmation:
            raise serializers.ValidationError("Код подтверждения неверный или уже использован.")


        data['user'] = user
        data['confirmation'] = confirmation
        return data


class ResendConfirmationSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate_username(self, value):
        # Проверяем, существует ли пользователь
        if not User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Если пользователь существует, письмо с кодом будет отправлено.")
        return value


class ConfirmCodeSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    confirmation_code = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = User.objects.get(username=data['username'])
            confirmation = ConfirmationCode.objects.get(user=user, code=data['confirmation_code'])
        except User.DoesNotExist:
            raise serializers.ValidationError('Если пользователь существует, письмо с кодом будет отправлено.')

        return data


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    username = serializers.CharField()
    password = serializers.CharField()

    class Meta:
        fields = ('username', 'password')
