# Generated by Django 3.1.14 on 2023-06-16 09:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dns_grpc', '0027_dnszoneaxfripacl_dnszoneaxfrnotify_reversednszoneaxfripacl_reversednszoneaxfrnotify'),
    ]

    operations = [
        migrations.AddField(
            model_name='dnszoneaxfripacl',
            name='last_used',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='dnszoneaxfripacl',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='dnszoneaxfrnotify',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='dnszoneaxfrsecrets',
            name='last_used',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='dnszoneaxfrsecrets',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='dnszoneupdatesecrets',
            name='last_used',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='dnszoneupdatesecrets',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='reversednszoneaxfripacl',
            name='last_used',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='reversednszoneaxfripacl',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='reversednszoneaxfrnotify',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='reversednszoneaxfrsecrets',
            name='last_used',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='reversednszoneaxfrsecrets',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
    ]
