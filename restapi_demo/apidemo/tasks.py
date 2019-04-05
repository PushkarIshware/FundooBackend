"""
******************************************************************************
* Purpose:  Service File for Celery and RabitMQ.
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   28-3-2018
*
******************************************************************************
"""
from django.contrib.auth.models import User
from .views import *
from celery import Celery
from celery import shared_task


@shared_task
def demo_celery():
    return 'celery-------------------------------works'


@shared_task
def Send_mail(username):
    print(username)
    user = User.objects.get(username=username)
    # print(email)
    uname = str(user.username)
    email = str(user.email)
    message = render_to_string('reg_mail.html', {
        'user': uname,
        'domain': 'http://127.0.0.1:8000',
        'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
        'token': account_activation_token.make_token(user),
    })
    mail_subject = 'Activate your account...'
    to_email = email
    send_email = EmailMessage(mail_subject, message, to=[to_email])
    send_email.send()
    return "email sent"


@shared_task
def Auto_Delete_Archive(uname):
    res = {
        "message": "Something went wrong",
        "data": "",
        "success": False
    }
    try:
        if uname:
            user = User.objects.get(username=uname).pk

            # archive to trash                  Exclude if NONE row but take if NOT-NONE
            archive_list = Note.objects.filter(~Q(archive_time=None), user_id=user, is_archived=True).values('archive_time',
                                                                                                             'id',
                                                                                                             'trash_time')
            # print(archive_list, 'archive')

            today = datetime.datetime.today().date()  # today's date

            # add 10 days to archive_time and store to end_date
            for i in archive_list:
                # archive_time for each note and add 10 days
                end_achive = i['archive_time'] + datetime.timedelta(days=10)
                print(end_achive)

                archive_to_trash = []                       # archive to trash notes
                if end_achive.date() == today:     # if end_date == today means 10 days over,then move the note to
                    # trash.
                    item = Note.objects.get(id=i['id'])     # gets the note by id
                    item.is_deleted = True                  # moves to trash.
                    item.save()                             # saves the note.
                    archive_to_trash.append(item)

            # print(archive_to_trash)

            # from trash to delete

            # Exclude if NONE row but take if NOT-NONE
            trash_list = Note.objects.filter(~Q(trash_time=None), user_id=user, is_deleted=True).values(
                'id', 'trash_time')
            # print(trash_list, 'delete')

            for j in trash_list:
                end_trash = j['trash_time'] + datetime.timedelta(days=7)
                print(end_trash)

                trash_to_delete = []                    # trash to deleted
                if end_trash.date() == today:           # if trash date == today date
                    item = Note.objects.get(id=i['id']) # get that note details from database
                    item.delete()                       # delete that row entry forever
                    trash_to_delete.append(item)
            # print(trash_to_delete)
            res["message"]="Auto archiving and deleting running"
            res["data"]= {}
            res["success"]=True
            return "background running"
            # return HttpResponse(res)
        else:
            res["message"] = "User not found"
            # return HttpResponse(res)
            return "user not found"
    except Exception as e:
            print(res)
