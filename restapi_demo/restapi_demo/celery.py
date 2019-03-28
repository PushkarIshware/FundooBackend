import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'restapi_demo.settings')

app = Celery('restapi_demo')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()