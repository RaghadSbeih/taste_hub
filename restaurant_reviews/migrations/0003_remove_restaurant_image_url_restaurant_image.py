# Generated by Django 5.2.3 on 2025-06-28 18:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restaurant_reviews', '0002_alter_user_role'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='restaurant',
            name='image_url',
        ),
        migrations.AddField(
            model_name='restaurant',
            name='image',
            field=models.ImageField(blank=True, null=True, upload_to='restaurant_images/'),
        ),
    ]
