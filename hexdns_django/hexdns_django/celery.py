import os
import celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'as207960_domains.settings')

app = celery.Celery('hexdns_django')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_state_db="/celery-state/celery-state.db",
)
app.autodiscover_tasks()
