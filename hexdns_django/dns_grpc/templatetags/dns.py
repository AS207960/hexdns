from django import template
import base64

register = template.Library()


@register.filter(name="b64_encode")
def b64encode(value):
    return base64.b64encode(value).decode("ascii")
