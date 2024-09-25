from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.utils.crypto import get_random_string

from auth_app.models import User, ConfirmationCode
from auth_app.utils import send_email_in_background


@receiver(post_save, sender=User)
def create_confirm_code(sender, instance, created, **kwargs):
    ConfirmationCode.objects.create(
        user=instance,
        code=get_random_string(6, allowed_chars='0123456789'),
        sent_at=timezone.now()
    )


@receiver(post_save, sender=User)
def send_notification(sender, instance, created, **kwargs):
    if created:
        # Запуск отправки письма в фоновом потоке
        send_email_in_background(instance, settings.EMAIL_HOST_USER, [instance.email])
