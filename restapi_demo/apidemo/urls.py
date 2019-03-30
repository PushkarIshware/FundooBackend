"""
******************************************************************************
* Purpose:  App URL file.
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   11-3-2018
*
******************************************************************************
"""

from django.conf.urls import url
from django.contrib import admin
from django.urls import path, include
from apidemo import views
from apidemo import urls
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)

urlpatterns = [

    path('admin/', admin.site.urls),

    # Rest Registration
    path('api/registration', views.RestRegistration.as_view(), name="RestRegistration"),

    # Rest Login
    path('api/login', views.RestLogin.as_view(), name="RestLogin"),

    
    # Note
    path('api/note', views.AddNote.as_view(), name="AddNote"),

    # ShowNotes
    path('api/shownotes', views.ShowNotes.as_view(), name='ShowNotes'),

    # UpdateNote
    path('api/updatenote/<int:pk>', views.UpdateNote.as_view(), name='UpdateNote'),

    # DeleteNote
    path('api/deletenote/<int:pk>', views.DeleteNote.as_view(), name='DeleteNote'),

    # PinUnpinNote
    path('api/pinunpin/<int:pk>', views.PinUnpinNote.as_view(), name='PinUnpinNote'),

    # Reminder
    path('api/reminder', views.Reminder.as_view(), name='Reminder'),

    # ArchiveNote
    path('api/archive/<int:pk>', views.ArchiveNote.as_view(), name='ArchiveNote'),

    # CreateLabel
    path('api/createlabel', views.CreateLabel.as_view(), name="CreateLabel"),

    # Showlabels
    path('api/showlabel', views.Showlabels.as_view(), name="Showlabels"),

    # DeleteLabel
    path('api/deletelabel/<int:pk>', views.DeleteLabel.as_view(), name="DeleteLabel"),

    # MapLabel
    path('api/maplabel', views.MapLabel.as_view(), name="MapLabel"),

    # GetMapLabels
    path('api/getmaplabels', views.GetMapLabels.as_view(), name="GetMapLabels"),

    # RemoveMapLabel/card_id/map_label_id
    path('api/removemaplabel/<int:pk>', views.RemoveMapLabel.as_view(), name="RemoveMapLabel"),

    # AddCollaborator
    path('api/addcollaborator', views.AddCollaborator.as_view(), name="AddCollaborator"),

    # RestProfile
    path('api/RestProfile', views.RestProfile.as_view(), name="RestProfile"),
    
    # get_url
    path('api/get_url', views.ImageUrl.as_view(), name="RestProfile"),

    # ShowCollaborators
    path('api/sc', views.ShowCollaborators.as_view(), name="RestProfile"),

    # Delete Collaborator
    path('api/removemcollaborator/<int:pk>', views.DeleteCollaborator.as_view(), name="DeleteCollaborator"),

    # SetReminder
    path('api/set_reminder/<int:pk>', views.SetReminder.as_view(), name='UpdateNote'),

    # social Login
    url(r'^oauth/', include('social_django.urls', namespace='social')),
    url(r'^home$', views.home, name='home'),


    # date
    path('api/date', views.date, name="date"),

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
