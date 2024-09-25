from django.contrib import admin
from auth_app.models import User, ConfirmationCode


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'username',)
    list_display_links = ('id', 'username',)


@admin.register(ConfirmationCode)
class ConfirmationCodeAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'code', 'sent_at',)
    list_display_links = ('id', 'user', 'code', 'sent_at',)
