# Generated by Django 2.1.5 on 2019-02-22 11:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apidemo', '0002_remove_note_created_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='note',
            name='color',
            field=models.CharField(default='#ffffff', max_length=50),
        ),
    ]