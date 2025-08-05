from datetime import datetime
from django.db import connection

class DBLogHandler:
    @staticmethod
    def insert_log(level: str, source: str, message: str):
        now = datetime.now()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO logs (created_at, level, source, message)
                    VALUES (%s, %s, %s, %s)
                """, [now, level.upper(), source, message])
        except Exception as e:
            print(f"[DBLogHandler] Failed to insert log: {e}")