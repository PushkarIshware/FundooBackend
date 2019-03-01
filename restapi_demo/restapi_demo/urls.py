from django.conf.urls import url
from django.contrib import admin
from django.urls import path, include
from apidemo import views

from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,

)


urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # Rest Registration
    path('api/registration', views.RestRegistration.as_view(), name="RestRegistration"),

    # Rest Login
    path('api/login', views.RestLogin.as_view(), name="RestLogin"),

    # Profile
    path('api/profile', views.UploadImg, name="Profile"),

    # Note
    path('api/note', views.AddNote.as_view(), name="AddNote"),

    # ShowNotes
    path('api/shownotes', views.ShowNotes.as_view(), name='ShowNotes'),

    # UpdateNote
    path('api/updatenote/<int:pk>', views.UpdateNote.as_view(), name='UpdateNote'),


    # Email Activation
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'),












    # Reset Password
    url(r'^password_reset/$', PasswordResetView.as_view(), name='password_reset'),
    url(r'^password_reset/done/$', PasswordResetDoneView.as_view(), name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    url(r'^reset/done/$', PasswordResetCompleteView.as_view(), name='password_reset_complete'),




]
