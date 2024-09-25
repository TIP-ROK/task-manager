from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    verified_email = models.BooleanField(default=False)


class ConfirmationCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    sent_at = models.DateTimeField(auto_now_add=True)
    resent_at = models.DateTimeField(null=True, blank=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.code}"
