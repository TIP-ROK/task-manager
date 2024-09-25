import threading

from django.core.mail import send_mail

from auth_app.models import ConfirmationCode


def send_email_in_background(instance, from_email, recipient_list):
    """
        Функция для отправки письма в параллельном потоке
    """
    subject = "Подтверждение регистрации код"
    message = f"Код подтверждения: {ConfirmationCode.objects.filter(user=instance).first().code}"
    email_thread = threading.Thread(
        target=send_mail,
        args=(subject, message, from_email, recipient_list),
    )
    email_thread.start()
