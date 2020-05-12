# Generated by Django 3.0.5 on 2020-05-12 13:24

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('dns_grpc', '0005_reversednszone_zsk_private'),
    ]

    operations = [
        migrations.AlterField(
            model_name='sshfprecord',
            name='host_key',
            field=models.TextField(verbose_name='Host key (from /etc/ssh/ssh_host_ed25519_key.pub etc.)'),
        ),
        migrations.CreateModel(
            name='DynamicAddressRecord',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('record_name', models.CharField(default='@', max_length=255, verbose_name='Record name (@ for zone root)')),
                ('ttl', models.PositiveIntegerField(verbose_name='Time to Live (seconds)')),
                ('current_ipv4', models.GenericIPAddressField(blank=True, null=True, protocol='ipv4')),
                ('current_ipv6', models.GenericIPAddressField(blank=True, null=True, protocol='ipv6')),
                ('password', models.CharField(max_length=255)),
                ('zone', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dns_grpc.DNSZone')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]