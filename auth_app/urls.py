from django.urls import path

from auth_app.views import RegistrationAPIView, ResendConfirmationEmailView, ConfirmEmailView, LoginView, LogoutView

urlpatterns = [
    path('confirm-email/', ConfirmEmailView.as_view(), name='confirm_email'),
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('resend-confirm/', ResendConfirmationEmailView.as_view(), name='resend_confirm'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='login'),
]
