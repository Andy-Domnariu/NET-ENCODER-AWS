from src.apps.device_registry.models import DeviceRegistry
from typing import Optional
from src.lib.utils.logger import Logger
from django.apps import apps
from src.lib.omnitec_crypto.omnitec_crypto import OmnitecCrypto
from src.lib.utils.utils import Utils
log = Logger("device_registry_handler")

class DeviceRegistryHandler:
        
    @staticmethod
    def check_mac_exists(mac: str) -> bool:
        return DeviceRegistry.objects.filter(mac=mac).exists()

    @staticmethod
    def register_mac(mac_input) -> dict:
        """
        mac_input puede ser un string o una lista de MACs.
        Devuelve un dict con listas de registradas, duplicadas e inválidas.
        """
        def is_valid_mac(mac):
            return isinstance(mac, str) and len(mac) == 12 and all(c in "0123456789ABCDEF" for c in mac.upper())

        normalized_macs = Utils.normalize_mac(mac_input)
        macs = normalized_macs if isinstance(normalized_macs, list) else [normalized_macs]

        registered = []
        duplicates = []
        invalids = []

        for mac in macs:
            if not is_valid_mac(mac):
                invalids.append(mac)
                continue

            if DeviceRegistry.objects.filter(mac=mac).exists():
                duplicates.append(mac)
            else:
                try:
                    DeviceRegistry.objects.create(mac=mac)
                    registered.append(mac)
                except Exception as e:
                    log.error(f"💥 Error creando MAC {mac}: {e}")
                    invalids.append(mac)

        return {
            "registered": registered,
            "duplicates": duplicates,
            "invalids": invalids,
            "message": f"{len(registered)} nuevas, {len(duplicates)} duplicadas, {len(invalids)} inválidas"
        }

    @staticmethod
    def update_device(data: dict) -> dict:
        log.info(f"➡️ Starting update_device with data: {data}")

        mac = Utils.normalize_mac(data.get("mac") or "")
        instance = data.get("instance")
        new_ip = data.get("ip")
        new_port = data.get("port")

        log.info(f"➡️ Parsed MAC: {mac}, Instance: {instance}, IP: {new_ip}, Port: {new_port}")

        missing_fields = []
        if not mac:
            missing_fields.append("mac")
        if not instance:
            missing_fields.append("instance")
        if not new_ip:
            missing_fields.append("ip")
        if not new_port:
            missing_fields.append("port")

        if missing_fields:
            log.error(f"🚫 Missing fields: {missing_fields}")
            return {
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}"
            }

        device = DeviceRegistry.objects.filter(mac=mac).first()
        if not device:
            log.error(f"⚠️ MAC {mac} not found.")
            return {
                "success": False,
                "error": f"MAC {mac} is not registered. Cannot update."
            }

        log.info(f"✅ Device {device} found.")

        # if instance already set and differs, reject
        if device.instance and device.instance != instance:
            log.error(f"🚫 Instance mismatch: {device.instance} != {instance}")
            return {"success": False, "error": "Instance does not match."}

        # NEW: ensure no other device uses this same IP+port
        ip_port_conflict = DeviceRegistry.objects.exclude(mac=mac) \
            .filter(ip=new_ip, port=new_port) \
            .exists()
        log.info(f"➡️ IP/PORT conflict check result: {ip_port_conflict}")
        if ip_port_conflict:
            log.error(f"🚫 IP {new_ip} and Port {new_port} already used.")
            return {"success": False, "error": "IP/Port already in use."}

        # existing guards against changing IP or port once set
        if device.ip and device.ip != new_ip:
            log.error(f"🚫 Cannot change IP {device.ip} to {new_ip}")
            return {"success": False, "error": "Cannot change IP."}

        if device.port and device.port != new_port:
            log.error(f"🚫 Cannot change Port {device.port} to {new_port}")
            return {"success": False, "error": "Cannot change Port."}

        log.info(f"➡️ Updating fields now...")

        device.ip             = new_ip
        device.port           = new_port
        device.instance       = instance
        device.apikey         = data.get("apikey", device.apikey)
        device.is_revalidator = data.get("isRevalidator", device.is_revalidator)
        device.save()

        log.info(f"✅ Device {mac} updated successfully.")
        return {"success": True, "message": f"Device {mac} updated successfully."}
    
    @staticmethod
    def register_credentials(data: dict) -> dict:
        InstanceCredentials = apps.get_model('device_registry', 'InstanceCredentials')

        instance = data.get("instance")
        username = data.get("username")
        password = data.get("password")

        if not instance or not username or not password:
            return {"success": False, "error": "Missing required fields."}

        if InstanceCredentials.objects.filter(instance=instance).exists():
            return {
                "success": False,
                "error": f"Credentials for instance '{instance}' already exist."
            }

        crypto = OmnitecCrypto()
        encrypted_username = crypto.encrypt(username)
        encrypted_password = crypto.encrypt(password)

        InstanceCredentials.objects.create(
            instance=instance,
            username=encrypted_username,
            password=encrypted_password
        )

        return {
            "success": True,
            "message": f"Credentials registered in instance '{instance}'."
        }


    @staticmethod
    def get_all_macs() -> list[str]:
        """
        Fetches and returns all registered MAC addresses.
        """
        # returns a plain list of MAC strings
        return list(DeviceRegistry.objects.values_list("mac", flat=True))