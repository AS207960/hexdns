from django import forms
from . import models
import crispy_forms.helper
import crispy_forms.layout
import crispy_forms.bootstrap


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
