"""
******************************************************************************
* Purpose:  Project urls
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   11-3-2018
*
******************************************************************************
"""

from django.contrib import admin
from django.urls import path, include
from apidemo import views
from apidemo import urls


urlpatterns = [

    # apidemo App URLs
    path('', include('apidemo.urls')),

    # Admin
    path('admin/', admin.site.urls),

]
