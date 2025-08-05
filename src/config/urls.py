from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("apps.net_encoder.urls")),
    path("device/", include("apps.device_registry.urls")),
    path("revalidator/", include("apps.revalidator.urls")),
]
