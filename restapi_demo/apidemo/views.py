"""
******************************************************************************
* Purpose:  APIs (Register,Login,uploadImage,AddNote,DeleteNote,...).
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   11-3-2018
*
******************************************************************************
"""
import base64
import datetime
import io
import os

import botocore
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from rest_framework.generics import CreateAPIView, UpdateAPIView, DestroyAPIView
from rest_framework.response import Response
from .CustomDecorator import custom_login_required
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.http import HttpResponse, request
from django.contrib.auth import get_user_model, authenticate, login
import jwt
import json
from django.contrib.auth.models import User
from django.http import JsonResponse
from PIL import Image
import boto3
from .serializers import registrationSerializer
from django.views import View
from .models import Note, Label, Map_Label
from .LoginSerializer import LoginSerializer
from .NoteSerializer import NoteSerializer
from .LabelSerializer import LabelSerializer
from .MapLabelSerializer import MapLabelSerializer
from itertools import chain
from .tasks import *
from datetime import datetime

User = get_user_model()


def jwt_tok(request):
    uid = request.META['HTTP_AUTHORIZATION']

    # print('from a header---------------------------', uid)
    # print("uid -s ---", uid)
    userdata = jwt.decode(uid, "Cypher", algorithm='HS256')
    uname = userdata['username']
    valid = User.objects.get(username=uname)
    # print(valid, "validation given token")
    if valid:
        return uname
    else:
        return "invalid entry"


def activate(request, uidb64, token):
    """ this is email activation method for checking given email is valid or not. """

    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)  # gets the username
        if user and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()

            return HttpResponse("<h3>Account Activated...Please Log In")
        else:
            return HttpResponse('Activation link is invalid!')
    except(TypeError, ValueError, User.DoesNotExist):
        return HttpResponse('Something bad happened')


class RestRegistration(CreateAPIView):
    """ Registration API """

    serializer_class = registrationSerializer

    def post(self, request, *args, **kwargs):
        res = {"message": "something bad happened",
               "data": {},
               "success": False}
        username = request.data['username']
        email = request.data['email']
        password = request.data['password1']
        if username and email and password is not "":
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_active = False
            user.save()

            message = render_to_string('acc_active_email.html', {
                'user': user,
                'domain': request.META.get('HTTP_HOST'),
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                'token': account_activation_token.make_token(user),
            })
            mail_subject = 'Activate your account...'
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            # Send_mail.delay(username, email)
            res['message'] = "registered Successfully...Please activate your Account"
            res['success'] = True
            return Response(res)
        else:
            return Response(res)


class RestLogin(CreateAPIView):
    """ Login API """

    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        res = {"message": "something bad happened",
               "data": {},
               "success": False,
               "user_id": {}}
        try:
            username = request.data['username']
            if username is None:
                raise Exception("Username is required")
            password = request.data['password']
            if password is None:
                raise Exception("password is required")
            user = authenticate(username=username, password=password)
            # print('user-->', user)

            if user:
                if user.is_active:
                    # login(request, user)
                    # user_id = request.user
                    payload = {'username': username, 'password': password}
                    # token = jwt.encode(payload, "secret_key", algorithm='HS256').decode('utf-8')
                    jwt_token = {
                        'token': jwt.encode(payload, os.getenv("SIGNATURE"), algorithm='HS256').decode('utf-8')
                    }
                    token = jwt_token['token']
                    res['message'] = "Logged in Successfully"
                    res['data'] = {"token": token}
                    res['success'] = True
                    return Response(res)
                else:
                    return Response(res)
            if user is None:
                return Response(res)
        except Exception as e:
            # print(e)
            return Response(res)


class AddNote(CreateAPIView):
    """
        This API is used to add notes of logged in user.
        Parameter: Username from token and (Title, Description, Color, etc.).
        CreateAPIView: Used for Create operations (Method-POST)
    """

    serializer_class = NoteSerializer

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        uname = request.user_id
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            uid = User.objects.get(username=uname).pk
            serializer = NoteSerializer(data=request.data)

            if request.data['title'] and request.data['description'] is None:
                raise Exception("title and description required ")

            if serializer.is_valid():
                # serializer.user_id = uid
                serializer.save(user_id=uid)
                res['message'] = "note added"
                res['success'] = True
                return Response(res)
            return Response(res)
        except Exception as e:
            print(res, e)


class ShowNotes(View):
    """
    This API is used to show all notes of logged in user.
    Parameter: Username from token.
    View: Used for read-only operations (Method-get)
    """

    @method_decorator(custom_login_required)
    def get(self, request):
        uname = request.user_id
        global note_data
        res = {
            'message': 'Something bad happened',
            'data': {},
            'label': {},
            'success': False
        }
        try:
            uid = User.objects.get(username=uname).pk
            note_data = Note.objects.filter(user_id=uid).values('id', 'title', 'description', 'is_archived', 'reminder',
                                                                'user', 'color', 'is_pinned', 'is_deleted', 'label',
                                                                'collaborate')
            demo = []
            for i in note_data:
                if Note.collaborate.through.objects.filter(note_id=i['id']).exists():
                    demo.append(i['id'])

            data = set(demo)
            new = list(data)

            cola_with = Note.collaborate.through.objects.filter(note_id__in=new).values()

            names = []
            for i in cola_with:
                item = User.objects.filter(id=i['user_id']).values('id', 'username')
                names.append(item)

            n = []
            for i in names:
                n.append(i)

            name_list = []
            for i in names:
                name_list.append(i)

            data_list = []
            for i in note_data:
                data_list.append(i)
            note_json = json.dumps(data_list)

            items = Note.collaborate.through.objects.filter(user_id=uid).values()

            names = []
            for i in items:
                j = User.objects.get(id=i['user_id'])
                # print(j.username)
                names.append(str(j))

            collab = []
            for i in items:
                collab.append(i['note_id'])
            # print('collab note id',collab)

            collab_notes = Note.objects.filter(id__in=collab).values('id', 'title', 'description', 'is_archived',
                                                                     'reminder',
                                                                     'user', 'color', 'is_pinned', 'is_deleted',
                                                                     'label')

            collab_json = []
            for i in collab_notes:
                collab_json.append(i)
            cj = json.dumps(collab_json)
            result_list = list(chain(data_list, collab_json))
            result_json = json.dumps(result_list)
            res['message'] = "Showing data."
            res['data'] = note_json
            res['success'] = True
            j = json.dumps(res)
            demo_celery.delay()
            return HttpResponse(result_json)

        except Exception as e:
            print(res, e)


class UpdateNote(UpdateAPIView):
    """Update Notes API"""

    """
        This API is used to Update notes of logged in user.
        Parameter: Username from token, Note id and (Title, Description, Color, etc.).
        UpdateAPIView: Used for Edit(Update,Delete) operations (Method-POST)
    """

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            queryset = Note.objects.get(pk=request.data['id'])

            item = Note.objects.get(pk=request.data['id'])
            title = request.data['title']
            des = request.data['description']
            color = request.data['color']
            remainder = request.data['reminder']

            item.title = title
            item.description = des
            item.color = color
            item.reminder = remainder

            item.save()
            # UpdateNote()

            res['message'] = "Update Successfully"
            res['success'] = True

            return Response(res)
        except Exception as e:
            print(res, e)


class DeleteNote(UpdateAPIView):
    """Delete Notes API"""

    """
        This API is used to Delete notes of logged in user.
        Parameter: Username from token and Note id.
        UpdateAPIView: Used for Edit(Update,Delete) operations (Method-POST)
    """

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        uname = request.user_id
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            item = Note.objects.get(pk=request.data['id'])
            delete = request.data['is_deleted']
            item.is_deleted = delete
            item.save()
            res['message'] = "Delete Successfully"
            res['success'] = True
            return Response(res)
        except Exception as e:
            print(res, e)


class PinUnpinNote(UpdateAPIView):
    """ PinUnpin Notes API """

    """
    This API is used to Pin or Unpin notes of logged in user.
    Parameter: Username from token and Note id.
    UpdateAPIView: Used for Edit(Update,Delete) operations (Method-POST)
    """

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            item = Note.objects.get(pk=request.data['id'])
            print(item)
            print(item.id)
            pin = request.data['is_pinned']
            item.is_pinned = pin
            item.save()
            res['message'] = "Pinunpin Successfully"
            res['success'] = True
            return Response(res)
        except Exception as e:
            print(res, e)


class SetReminder(UpdateAPIView):
    """
    This API is used to Set Reminder notes of logged in user.
    Parameter(s): Username,Note id,Date.
    UpdateAPIView: Used for Edit(Update,Delete) operations (Method-POST)
    """

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            queryset = Note.objects.get(pk=request.data['id'])

            item = Note.objects.get(pk=request.data['id'])
            remainder = request.data['reminder']
            item.reminder = remainder
            item.save()
            res['message'] = "Update Successfully"
            res['success'] = True

            return Response(res)
        except Exception as e:
            print(res, e)


class Reminder(View):
    """Reminder notes API"""

    """
        This API is used to View Reminder notes of logged in user.
        Parameter(s): Username,Note id.
        View: Used for View or Display operations (Method-GET)
    """

    @method_decorator(custom_login_required)
    def get(self, request):

        global note_data
        uname = request.user_id

        uid = uid = User.objects.get(username=uname).pk
        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        try:
            note_data = Note.objects.filter(user_id=uid).values('id', 'title', 'description', 'reminder', )
            rem_notes = []
            for i in note_data:
                if i['reminder']:
                    rem_notes.append(i)
            print(rem_notes)
            z = json.dumps(rem_notes)
            return HttpResponse(z)
        except Exception as e:
            print(res, e)


class ArchiveNote(UpdateAPIView):
    """ArchiveNotes Notes API"""

    """
        This API is used to Set Archive notes of logged in user.
        Parameter(s): Username,Note id,Archive_Value.
        UpdateAPIView: Used for Edit(Update,Delete) operations (Method-POST)
    """

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            queryset = Note.objects.get(pk=request.data['id'])
            item = Note.objects.get(pk=request.data['id'])
            print(item)
            print(item.id)
            archive = request.data['is_archived']
            item.is_archived = archive
            item.save()
            res['message'] = "Archived Successfully"
            res['success'] = True
            return Response(res)
        except Exception as e:
            print(res, e)


class DeleteLabel(DestroyAPIView):
    """Delete labels API"""

    """
        This API is used to Set Delete notes of logged in user.
        Parameter(s): Username,Note id,Delete_Value.
        DestroyAPIView: Used for Delete operations (Method-Delete)
    """

    @method_decorator(custom_login_required)
    def delete(self, request, pk):
        print("inside Delete")

        res = {
            'message': 'label Deleted',
            'data': {},
            'success': True
        }
        Label.objects.get(pk=pk).delete()
        return Response(res)


class CreateLabel(CreateAPIView):
    """Create Labels API"""

    """
    This API is used to Create Labels.
    Parameter(s): Username,Note id,Label_name.
    CreateAPIView: Used for Create operations (Method-POST)
    """

    serializer_class = LabelSerializer

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        uname = request.user_id
        print('inside post')
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            print(uname, "-***************************")
            uid = User.objects.get(username=uname).pk
            print(uid)
            print(request.data)
            # note_id = Note.objects.get(pk=request.data['id'])

            serializer = LabelSerializer(data=request.data)
            label = request.data['label_name']
            if request.data['label_name'] is "":
                raise Exception("label name required ")

            if serializer.is_valid():
                serializer.user_id = uid
                serializer.save(user_id=uid)
                res['message'] = "label added"
                res['success'] = True
                return JsonResponse(res)
            return JsonResponse(res)
        except Exception as e:
            print(res, e)


class Showlabels(View):
    """Show labels API"""

    """
        This API is used to Show Labels.
        Parameter(s): Username.
        View: Used for Create operations (Method-GET)
    """

    @method_decorator(custom_login_required)
    def get(self, request):
        global note_data
        uname = jwt_tok(request)
        uname = jwt_tok(request)
        # print(uname,"------------------------------------")

        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        try:
            uid = User.objects.get(username=uname).pk
            note_data = Label.objects.filter(user_id=uid).values('id', 'label_name', 'user')
            data_list = []
            for i in note_data:
                data_list.append(i)
            z = json.dumps(data_list)
            res['message'] = "Showing data."
            res['data'] = z
            res['success'] = True
            return HttpResponse(z)

        except Exception as e:
            print(res, e)


class MapLabel(CreateAPIView):
    """Map labels API"""

    """
        This API is used to Map Labels to perticular Note.
        Parameter(s): Username,Note id,Label_name.
        CreateAPIView: Used for Mapping operations (Method-POST)
    """

    serializer_class = MapLabelSerializer

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        uname = request.user_id
        print('inside post')
        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        if User.objects.get(username=uname).pk:
            uid = User.objects.get(username=uname).pk
            card = Note.objects.get(pk=request.data['id'])
            cid = card.id
            label = Label.objects.get(pk=request.data['label_id'])
            lid = label.id
            mapping = Map_Label.objects.create(label_id=Label.objects.get(id=lid),
                                               user=User.objects.get(id=uid),
                                               note=Note.objects.get(id=cid),
                                               map_label_name=Label.objects.get(label_name=label))
            res['message'] = 'label added'
            res['success'] = True
            res['data'] = {"label_id": lid}
            return Response(res)


class GetMapLabels(View):
    """Show Map labels API"""

    """
        This API is used to View Mapped Labels on particular note.
        Parameter(s): Username.
        View: Used for View operations (Method-GET)
    """

    @method_decorator(custom_login_required)
    def get(self, request):
        uname = request.user_id
        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        try:
            uid = User.objects.get(username=uname).pk
            note_data = Map_Label.objects.filter(user_id=uid).values('id', 'user_id',
                                                                     'map_label_name',
                                                                     'note_id')
            data_list = []
            for i in note_data:
                data_list.append(i)
            z = json.dumps(data_list)
            res['message'] = "Showing data."
            res['data'] = z
            res['success'] = True
            return HttpResponse(z)
        except Exception as e:
            print(res, e)


class RemoveMapLabel(DestroyAPIView):
    """Remove labels API"""
    """
        This API is used to Delete label on particular note.
        Parameter(s): Username,Note id,Label_id.
        DestroyAPIView: Used for Delete operations (Method-DELETE)
    """

    @method_decorator(custom_login_required)
    def delete(self, request, pk):
        print("inside Delete")

        res = {
            'message': 'label removed successfully',
            'data': {},
            'success': True
        }
        Map_Label.objects.get(pk=pk).delete()
        return Response(res)


class RestProfile(CreateAPIView):
    """Upload Profile Photo API"""

    """
        This API is used to upload Profile Picture of logged in user to S3 Bucket.
        Parameter(s): Username,Image.
        CreateAPIView: Used for Upload operations (Method-POST)
    """

    serializer_class = NoteSerializer

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        print("inside post")
        res = {
            'message': 'Image Uploaded',
            'data': {},
            'success': True
        }
        uname = request.user_id
        pic = request.data['profile1']

        # working code
        pic = pic[22:]
        image = base64.urlsafe_b64decode(pic)
        buf = io.BytesIO(image)
        img = Image.open(buf, 'r').convert("RGB")
        img.show()
        out_img = io.BytesIO()
        s3 = boto3.client('s3')
        img.save(out_img, format="jpeg")
        img.seek(0)
        print('------------', img)
        img3 = Image.open(out_img)
        print('img 3-----', img3)
        print(img3.size)
        img3.save(os.path.join('/home/admin1/Desktop/' + str(uname) + '.jpeg'), 'JPEG')
        file = open('/home/admin1/Desktop/' + str(uname) + '.jpeg', 'rb')
        s3.upload_fileobj(file, 'bucketprofile', Key=str(uname) + ".jpeg", ExtraArgs={'ACL': 'public-read'})
        z = json.dumps(res)
        return HttpResponse(z)


class ImageUrl(View):
    """ Show Profile Photo API """

    """
        This API is used to Get Profile Picture of logged in user from S3 Bucket.
        Parameter(s): Username,Image.
        View: Used for Upload operations (Method-GET)
    """

    @method_decorator(custom_login_required)
    def get(self, request):
        uname = request.user_id

        link = "https://s3.ap-south-1.amazonaws.com/bucketprofile/" + str(uname) + ".jpeg"

        s3 = boto3.resource('s3')
        try:
            s3.Object('bucketprofile', str(uname) + ".jpeg").load()
            res = {"data": link, "username": str(uname)}
            res_json = json.dumps(res)
            return HttpResponse(res_json)

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                link = "https://s3.ap-south-1.amazonaws.com/bucketprofile/Default_Photo.jpeg"
                res = {"data": link, "username": str(uname)}
                res_json = json.dumps(res)
                return HttpResponse(res_json)


class AddCollaborator(CreateAPIView):
    """Add Collaborator API"""

    """
        This API is used to Add Collaborator to particular note.
        Parameter(s): Username,Note_id.
        CreateAPIView: Used for Upload operations (Method-POST)
    """

    serializer_class = NoteSerializer

    @method_decorator(custom_login_required)
    def post(self, request, *args, **kwargs):
        print("inside post")
        res = {
            'message': 'collaborated successfully',
            'data': {},
            'success': True
        }
        note_id = request.data['id']
        card_details = Note.objects.get(id=note_id)
        new_user = request.data['new_username']
        uid = User.objects.get(username=new_user)
        card_details.collaborate.add(uid)
        card_details.save()
        print(uid)

        return Response(res)


class ShowCollaborators(View):
    """ Show Collaborator API """

    """
        This API is used to Show Collaborator to particular note.
        Parameter(s): Username,Note_id.
        View: Used for Upload operations (Method-GET)
    """

    @method_decorator(custom_login_required)
    def get(self, request):
        uname = request.user_id
        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        uid = User.objects.get(username=uname).pk
        # note details
        note_q = Note.objects.filter(user_id=uid).values('id')
        print(note_q, 'ids of given usr notes from NOTE table')

        note_d = []
        for i in note_q:
            note_d.append(i['id'])
        print(note_d)

        q = Note.collaborate.through.objects.filter(note_id__in=note_d).values('note_id', 'user_id')
        print(q, 'present notes in collab')

        ids = []
        note_i = []
        for i in q:
            ids.append(i['user_id'])
            note_i.append(i['note_id'])
        print(ids)
        print(note_i)
        na = []
        for i in ids:
            name = User.objects.get(id=i)
            na.append(str(name))
            print(name)
        print(na)
        ok = []
        data = {"uid": "", "uname": "", "note_id": ""}
        for i, j, k in zip(ids, na, note_i):
            data = {"uid": i, "uname": j, "note_id": k}
            ok.append(data)

        result_json = json.dumps(ok)
        return HttpResponse(result_json)


class DeleteCollaborator(DestroyAPIView):
    """Delete Collaborator API"""

    """
        This API is used to Delete Collaborator to particular note.
        Parameter(s): Username,Note_id,Collaborator's_Name.
        DestroyAPIView: Used for Upload operations (Method-DELETE)
    """

    @method_decorator(custom_login_required)
    def delete(self, request, pk):
        print("inside Delete")

        res = {
            'message': 'Collaborator Deleted',
            'data': {},
            'success': True
        }
        obj = Note.collaborate.through.objects.get(note_id=pk)
        obj.delete()
        return Response(res)


def home(request):
    return render(request, 'home.html')


def date(request):
    today_date = datetime.now().date()
    print(type(today_date))
    uname = "ishware"

    uid = User.objects.get(username=uname).pk

    note_rem = Note.objects.filter(user_id=uid).values()
    # print(note_rem)

    date_type = []
    for i in note_rem:
        if i['reminder']:
            date_type.append(datetime.strptime(i['reminder'], '%d/%m/%Y').date())

    print(date_type)

    for i in date_type:
        print(i)
        z = i - today_date
        z = str(z)
        diff = z[0:1]
        diff_int = int(diff)
        # print(diff_int)

        mail_date_diff = diff_int // 2

        # b=datetime.datetime.timedelta(days=mail_date_diff)
        # dt = timedelta.days(str(mail_date_diff))
        # print(type(dt))
        # print(dt,'----------------')
        # # mail_date = today_date + datetime.timedelta(mail_date_diff)
        # print(mail_date)
