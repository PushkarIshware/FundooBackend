from django.conf.urls import url
from django.contrib import admin
from django.urls import path, include
from apidemo import views
from apidemo import urls



urlpatterns = [

    # apidemo App URLs
    path('', include('apidemo.urls')),

    # Admin
    path('admin/', admin.site.urls),

    # url(r'^oauth/', include('social_django.urls', namespace='social')),
]
