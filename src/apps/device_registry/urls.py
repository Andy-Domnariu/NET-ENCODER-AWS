from django.urls import path
from .views import RegisterDeviceView, DeviceExistsView, UpdateDeviceView, GetAllMACsView, PingView, RegisterInstanceCredentialsView

urlpatterns = [
    path("register/", RegisterDeviceView, name="register_device"),
    path("register-credentials/", RegisterInstanceCredentialsView),
    path("exists/", DeviceExistsView, name="check_device_exists"),
    path("update/", UpdateDeviceView, name="update_device"),
    path("maclist/", GetAllMACsView, name="maclist"),
    path("ping/", PingView, name="ping"),
]
