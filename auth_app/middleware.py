import logging


logger = logging.getLogger(__name__)


class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Получаем IP-адрес клиента
        ip_address = self.get_client_ip(request)

        # Логирование IP-адреса
        logger.info(f"Request from IP: {ip_address}")

        # Передаем запрос дальше по цепочке
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        # Проверка заголовков, которые могут содержать IP (если используется прокси)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
