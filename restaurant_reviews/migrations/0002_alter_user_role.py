# Generated by Django 5.2.3 on 2025-06-28 17:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restaurant_reviews', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('user', 'User')], default='admin', max_length=50),
        ),
    ]
