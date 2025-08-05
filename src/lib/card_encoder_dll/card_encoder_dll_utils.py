from datetime import datetime, timedelta, timezone
from typing import Optional
from src.lib.utils.logger import Logger

logger = Logger("card_encoder_dll_utils")

class CardEncoderDllUtils:
    @staticmethod
    def convert_timestamp_to_lock_timezone(server_time: str, lock_timezone: str) -> str:
        """
        Converts a server timestamp to "YYYY/MM/DD HH:mm" format and adjusts it for the lock's timezone.
        
        :param server_time: Timestamp from the server (ISO format: "YYYY-MM-DDTHH:MM:SSZ")
        :param lock_timezone: Timezone offset in the format "GMT+X" or "GMT-X"
        :return: Adjusted timestamp as "YYYY/MM/DD HH:mm"
        """
        try:
            logger.info(f"Converting server timestamp {server_time} to lock timezone {lock_timezone}")
            # Step 1: Parse the server time (assumes it's in UTC format)
            server_dt = datetime.strptime(server_time, "%Y-%m-%dT%H:%M:%SZ")
            server_dt = server_dt.replace(tzinfo=timezone.utc)
            
            # Step 2: Parse the lock's timezone offset
            if "GMT" in lock_timezone:
                sign = -1 if "-" in lock_timezone else 1
                hours_offset = int(lock_timezone.replace("GMT", "").replace("+", "").replace("-", ""))
                delta = timedelta(hours=sign * hours_offset)
                lock_dt = server_dt + delta
            else:
                raise ValueError("Invalid timezone format. Must be 'GMT+X' or 'GMT-X'")
            
            # Step 3: Format the adjusted time as "YYYY/MM/DD HH:mm"
            formatted_time = lock_dt.strftime("%Y/%m/%d %H:%M")
            logger.info(f"Converted time: {formatted_time}")
            return formatted_time
        
        except Exception as e:
            logger.error(f"Error converting timestamp: {e}")
            raise ValueError(f"Error converting timestamp: {e}")

    @staticmethod
    def convert_timestamp_to_server_timezone(lock_timestamp: str, lock_timezone: str) -> Optional[str]:
        """
        Converts a timestamp from the lock's timezone back to server time.

        Args:
            lock_timestamp (str): The timestamp from the lock in format "YYYY/MM/DD HH:mm".
            lock_timezone (str): The timezone offset of the lock (e.g., "GMT+3", "GMT-5").

        Returns:
            Optional[str]: The converted timestamp in "YYYY-MM-DDTHH:MM:SSZ" format or None if an error occurs.
        """
        try:
            logger.info(f"Converting lock timestamp {lock_timestamp} from timezone {lock_timezone} to server timezone")
            # Parse the lock timestamp
            lock_time = datetime.strptime(lock_timestamp, "%Y/%m/%d %H:%M")

            # Extract the offset from the lock's timezone
            offset_sign = 1 if "+" in lock_timezone else -1
            offset_hours = int(lock_timezone.replace("GMT", "").strip())
            server_time = lock_time - timedelta(hours=offset_sign * offset_hours)

            # Format the adjusted time in ISO format "YYYY-MM-DDTHH:MM:SSZ"
            converted_time = server_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            logger.info(f"Converted time: {converted_time}")
            return converted_time
        
        except Exception as e:
            logger.error(f"Error converting timestamp to server timezone: {e}")
            return None
