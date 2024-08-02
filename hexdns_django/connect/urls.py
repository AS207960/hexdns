from django.urls import path
from . import views

urlpatterns = [
    path("v2/<str:domain>/settings", views.domain_settings, name="domain_settings"),
    path("api/v2/domainTemplates/providers/<str:provider_id>/services/<str:service_id>", views.check_template, name="check_template"),
    path("sync/v2/domainTemplates/providers/<str:provider_id>/services/<str:service_id>/apply", views.sync_apply, name="sync_apply"),
]
