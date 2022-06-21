import os
import celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'as207960_domains.settings')

app = celery.Celery('hexdns_django')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
