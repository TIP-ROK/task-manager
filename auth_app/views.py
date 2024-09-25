from datetime import timezone

from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from auth_app.models import ConfirmationCode
from auth_app.serializers import ResendConfirmationSerializer, EmailConfirmationSerializer, ConfirmCodeSerializer, \
    LoginSerializer
from auth_app.utils import send_email_in_background
from task_manager import settings
from rest_framework.throttling import UserRateThrottle
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework import exceptions

User = get_user_model()


class RegistrationAPIView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [UserRateThrottle]

    @swagger_auto_schema(
        operation_description="Регистрация нового пользователя.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Уникальное имя пользователя'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Уникальный адрес электронной почты'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Пароль пользователя'),
            },
            required=['username', 'email', 'password']
        ),
        responses={
            201: openapi.Response("Регистрация прошла успешно."),
            400: openapi.Response("Данные некорректны или уже существуют."),
            500: openapi.Response("Ошибка регистрации. Попробуйте позже.")
        }
    )

    def post(self, request, *args, **kwargs):
        """
        Регистрация нового пользователя.

        Принимает данные:
        - username: строка, уникальное имя пользователя
        - email: строка, уникальный адрес электронной почты
        - password: строка, пароль пользователя

        Возвращает:
        - 201 Created, если регистрация прошла успешно.
        - 400 Bad Request, если данные некорректны или уже существуют.
        """
        try:
            username = request.data.get('username')
            email = request.data.get('email')
            password = request.data.get('password')

            if not username or not email or not password:
                raise ValidationError("Все поля обязательны.")

            # Проверка на существование пользователя
            if User.objects.filter(username=username).exists():
                raise ValidationError("Пользователь с таким именем уже существует.")
            # if User.objects.filter(email=email).exists():
            #     raise ValidationError("Пользователь с таким адресом электронной почты уже существует.")

            User.objects.create_user(username=username, email=email, password=password, is_active=False)
            return Response('На вашу почту отправлено письмо с кодом подтверждения',status=status.HTTP_201_CREATED)

        except ValidationError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response({"detail": "Ошибка регистрации. Попробуйте позже."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConfirmEmailView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Подтверждение пользователя по коду, отправленному на почту.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Имя пользователя'),
                'code': openapi.Schema(type=openapi.TYPE_STRING, description='Код подтверждения'),
            },
            required=['username', 'code']
        ),
        responses={
            200: openapi.Response("Пользователь успешно подтвержден."),
            400: openapi.Response("Код неверный или уже использован."),
            404: openapi.Response("Пользователь не найден."),
            500: openapi.Response("Ошибка подтверждения. Попробуйте позже.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = EmailConfirmationSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            confirmation = serializer.validated_data['confirmation']

            # Проверяем, подтвержден ли уже email
            if user.verified_email:
                return Response({"detail": "Email уже подтвержден."}, status=status.HTTP_400_BAD_REQUEST)

            # Подтверждаем пользователя и email
            user.is_active = True
            user.verified_email = True  # Устанавливаем флаг подтверждения email
            user.save()

            # Обновляем статус кода подтверждения
            confirmation.is_confirmed = True
            confirmation.save()

            if not isinstance(user.username, str):
                print(f'user == {user.username}')
                raise TypeError("Expected a string value for username")

            # Генерируем JWT токены
            refresh = RefreshToken.for_user(user)

            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'detail': "Пользователь успешно подтвержден."
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        serializer = ConfirmCodeSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(username=serializer.validated_data['username'])
            user.is_active = True
            user.save()
            confirm_code = ConfirmationCode.objects.get(user=user, code=serializer.validated_data['confirmation_code'])
            confirm_code.sent_at = now()
            confirm_code.save()

            # Генерация JWT токенов
            refresh = RefreshToken.for_user(user)
            print(refresh)
            print(refresh.access_token)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendConfirmationEmailView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [UserRateThrottle]

    @swagger_auto_schema(
        operation_description="Повторная отправка кода подтверждения на почту пользователя.",
        request_body=ResendConfirmationSerializer,
        responses={
            200: openapi.Response(
                description="На вашу почту отправлено письмо с кодом подтверждения.",
                examples={
                    "application/json": {
                        "detail": "На вашу почту отправлено письмо с кодом подтверждения."
                    }
                }
            ),
            400: openapi.Response(
                description="Ошибки валидации данных.",
                examples={
                    "application/json": {
                        "username": ["Это поле обязательно."]
                    }
                }
            ),
            429: openapi.Response(
                description="Слишком много запросов. Повторная отправка возможна не ранее, чем через 5 минут.",
                examples={
                    "application/json": {
                        "detail": "Повторная отправка возможна не ранее, чем через 5 минут."
                    }
                }
            ),
            500: openapi.Response(
                description="Ошибка на сервере. Попробуйте позже.",
                examples={
                    "application/json": {
                        "detail": "Ошибка подтверждения. Попробуйте позже."
                    }
                }
            )
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = ResendConfirmationSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            try:
                if not username:
                    raise ValidationError("Все поля обязательны.")

                user = User.objects.get(username=username)
                confirmation = ConfirmationCode.objects.filter(user=user).first()
                confirmation.code = get_random_string(6, allowed_chars='0123456789')
                confirmation.resent_at = now()
                confirmation.save()
                send_email_in_background(user, settings.EMAIL_HOST_USER, [user.email])
                return Response('На вашу почту отправлено письмо с кодом подтверждения', status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({"detail": "Если пользователь существует, письмо с кодом будет отправлено."}, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({'detail': 'Ошибка подтверждения. Попробуйте позже'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type='object',
            properties={
                'username': openapi.Schema(type='string'),
                'password': openapi.Schema(type='string'),
            },
            required=['username', 'password']
        ),
        responses={
            200: openapi.Schema(
                type='object',
                properties={
                    'token': openapi.Schema(type='string'),
                    'user_id': openapi.Schema(type='integer'),
                    'username': openapi.Schema(type='string')
                }
            )
        }
    )
    def post(self, request, *args, **kwargs):
        # Validate user credentials
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(username=serializer.validated_data['username'], password=serializer.validated_data['password'])

        if not user:
            raise exceptions.AuthenticationFailed(_('“The login or password was entered incorrectly. Try again.”'))

        # Generate a token for the user
        token, created = Token.objects.get_or_create(user=user)
        User.objects.filter(username=user).update(last_login=now())

        return Response({
            'token': token.key,
            'user_id': user.pk,
            'username': user.username
        })


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        # Delete the user's authentication token
        Token.objects.get(user=request.user).delete()
        return Response("Вы вышли из системы")
