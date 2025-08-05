from django.contrib import admin
from .models import DeviceRegistry

@admin.register(DeviceRegistry)
class DeviceRegistryAdmin(admin.ModelAdmin):
    list_display = ('mac', 'ip', 'port', 'instance', 'is_revalidator')
    search_fields = ('mac', 'ip', 'instance')
