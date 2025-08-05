from django.db import models

class DeviceRegistry(models.Model):
    mac = models.CharField(max_length=50, unique=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    instance = models.CharField(max_length=100, null=True, blank=True)
    apikey = models.CharField(max_length=255, null=True, blank=True)
    is_revalidator = models.BooleanField(default=False)

    configuracion = models.ForeignKey(
        'Configuracion',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='devices'
    )

    class Meta:
        app_label = 'device_registry'
        db_table = 'devices'
        constraints = [
            models.UniqueConstraint(fields=['ip', 'port'], name='unique_ip_port_pair')
        ]

    def __str__(self):
        return f"{self.mac} ({self.ip}:{self.port})"
    
class InstanceCredentials(models.Model):
    instance = models.CharField(max_length=100, unique=True)
    username = models.TextField()
    password = models.TextField()

    class Meta:
        db_table = 'credentials'
        constraints = [
            models.UniqueConstraint(fields=["instance"], name="unique_instance")
        ]

class Configuracion(models.Model):
    ip = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = 'configuracion'

    def __str__(self):
        return self.ip