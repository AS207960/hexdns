# Generated by Django 3.0.7 on 2020-07-25 14:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dns_grpc', '0016_hinforecord_locrecord_rprecord'),
    ]

    operations = [
        migrations.AddField(
            model_name='dnszone',
            name='resource_id',
            field=models.UUIDField(null=True),
        ),
        migrations.AddField(
            model_name='reversednszone',
            name='resource_id',
            field=models.UUIDField(null=True),
        ),
        migrations.AddField(
            model_name='secondarydnszone',
            name='resource_id',
            field=models.UUIDField(null=True),
        ),
    ]