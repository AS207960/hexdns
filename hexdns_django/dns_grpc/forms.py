from django import forms
from . import models
import crispy_forms.helper
import crispy_forms.layout
import crispy_forms.bootstrap


class ZoneForm(forms.Form):
    zone_root = forms.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Create"))


class SecondaryZoneForm(forms.Form):
    zone_root = forms.CharField()
    primary_server = forms.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))


class AddressRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name", "address", "ttl", "auto_reverse"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.AddressRecord
        fields = "__all__"
        exclude = ("id", "zone")


class DynamicAddressRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password'].disabled = True
        self.fields['password'].required = False
        self.fields['id'].disabled = True
        self.fields['id'].required = False
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "id", "password", "record_name", "ttl"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DynamicAddressRecord
        fields = "__all__"
        exclude = ("zone", "current_ipv4", "current_ipv6")


class CNAMERecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout("record_name", "alias", "ttl",)
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.CNAMERecord
        fields = "__all__"
        exclude = ("id", "zone")


class MXRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name", "exchange", "priority", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.MXRecord
        fields = "__all__"
        exclude = ("id", "zone")


class NSRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name", "nameserver", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.NSRecord
        fields = "__all__"
        exclude = ("id", "zone")


class TXTRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout("record_name", "data", "ttl",)
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.TXTRecord
        fields = "__all__"
        exclude = ("id", "zone")


class SRVRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name", "priority", "weight", "port", "target", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.SRVRecord
        fields = "__all__"
        exclude = ("id", "zone")


class CAARecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name", "flag", "tag", "value", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.CAARecord
        fields = "__all__"
        exclude = ("id", "zone")


class NAPTRRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name",
            "order",
            "preference",
            "flags",
            "service",
            "regexp",
            "replacement",
            "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.NAPTRRecord
        fields = "__all__"
        exclude = ("id", "zone")


class SSHFPRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name", "host_key", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.SSHFPRecord
        fields = "__all__"
        exclude = ("id", "zone")


class DSRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name", "key_tag", "algorithm", "digest_type", "digest", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DSRecord
        fields = "__all__"
        exclude = ("id", "zone")


class ReversePTRRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-4"
        self.helper.field_class = "col-lg-8"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_address", "pointer", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.PTRRecord
        fields = "__all__"
        exclude = ("id", "zone")


class ZoneImportForm(forms.Form):
    zone_data = forms.CharField(widget=forms.Textarea())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-2"
        self.helper.field_class = "col-lg-10"
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.layout.HTML("""
                <div class="alert alert-info" role="alert">
                    Paste a full or partial zone file in RFC 1035 format. We'll ignore any record types we don't support.
                </div>
            """),
            "zone_data",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Import"))


class GithubPagesForm(forms.Form):
    record_name = forms.CharField(max_length=255, initial="@", label="Record name (@ for zone root)")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-2"
        self.helper.field_class = "col-lg-10"
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Setup"))


class DMARCForm(forms.Form):
    policy = forms.ChoiceField(choices=(
        ("none", "No action"),
        ("quarantine", "Quarantine on fail"),
        ("reject", "Reject on fail")
    ))
    subdomain_policy = forms.ChoiceField(choices=(
        (None, "---"),
        ("none", "No action"),
        ("quarantine", "Quarantine on fail"),
        ("reject", "Reject on fail")
    ), required=False)
    percentage = forms.IntegerField(
        min_value=0, max_value=100, label="Percentage of messages to apply policy to", required=False
    )
    dkim_alignment = forms.ChoiceField(choices=(
        ("r", "Relaxed"),
        ("s", "Strict")
    ), label="DKIM alignment mode")
    spf_alignment = forms.ChoiceField(choices=(
        ("r", "Relaxed"),
        ("s", "Strict")
    ), label="SPF alignment mode")
    report_interval = forms.IntegerField(min_value=0, label="Reporting interval (seconds)", required=False)
    aggregate_feedback = forms.CharField(
        label="Aggregate feedback URIs (example: mailto:dmarc@example.com)", required=False
    )
    failure_feedback = forms.CharField(
        label="Failure information URIs (example: mailto:dmarc@example.com)", required=False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-3"
        self.helper.field_class = "col-lg-9"
        self.helper.layout = crispy_forms.layout.Layout(
            "policy",
            "subdomain_policy",
            "percentage",
            "dkim_alignment",
            "spf_alignment",
            "report_interval",
            "aggregate_feedback",
            "failure_feedback"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Generate"))
