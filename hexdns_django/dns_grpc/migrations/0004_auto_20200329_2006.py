# Generated by Django 3.0.4 on 2020-03-29 20:06

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("dns_grpc", "0003_auto_20200329_1957"),
    ]

    operations = [
        migrations.CreateModel(
            name="MXRecord",
            fields=[
                (
                    "dnszonerecord_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="dns_grpc.DNSZoneRecord",
                    ),
                ),
                ("exchange", models.CharField(max_length=255)),
                ("priority", models.PositiveIntegerField()),
            ],
            options={"verbose_name": "MX record", "verbose_name_plural": "MX records",},
            bases=("dns_grpc.dnszonerecord",),
        ),
        migrations.CreateModel(
            name="NSRecord",
            fields=[
                (
                    "dnszonerecord_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="dns_grpc.DNSZoneRecord",
                    ),
                ),
                ("nameserver", models.CharField(max_length=255)),
            ],
            options={"verbose_name": "NS record", "verbose_name_plural": "NS records",},
            bases=("dns_grpc.dnszonerecord",),
        ),
        migrations.AlterModelOptions(
            name="cnamerecord",
            options={
                "verbose_name": "CNAME record",
                "verbose_name_plural": "CNAME records",
            },
        ),
        migrations.RemoveField(model_name="reversednszonerecord", name="record_name",),
        migrations.AddField(
            model_name="reversednszonerecord",
            name="record_address",
            field=models.GenericIPAddressField(default=""),
            preserve_default=False,
        ),
    ]
