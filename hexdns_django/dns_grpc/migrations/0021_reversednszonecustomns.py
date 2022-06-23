# Generated by Django 3.1.14 on 2022-06-23 10:43

import as207960_utils.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dns_grpc', '0020_auto_20220527_1119'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReverseDNSZoneCustomNS',
            fields=[
                ('id', as207960_utils.models.TypedUUIDField(data_type='hexdns_rzonecustomns', primary_key=True, serialize=False)),
                ('nameserver', models.CharField(max_length=255, verbose_name='Name server')),
                ('dns_zone', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='custom_ns', to='dns_grpc.reversednszone')),
            ],
        ),
    ]
