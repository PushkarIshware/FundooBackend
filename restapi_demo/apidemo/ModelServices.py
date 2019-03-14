import json

from .models import *


def GetNotes(uid):
    note_data = Note.objects.filter(user_id=uid).values('id', 'title', 'description',
                                                   'is_archived', 'reminder',
                                                   'user', 'color', 'is_pinned',
                                                   'is_deleted', 'label')
    data_list = []
    for i in note_data:
        data_list.append(i)
    note_json = json.dumps(data_list)
    return note_json


