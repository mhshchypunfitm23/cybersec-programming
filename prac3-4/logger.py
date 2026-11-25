import logging
import json
import os
from datetime import datetime, timezone

class JsonSecurityFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_record.update(record.extra)
        return json.dumps(log_record, ensure_ascii=False)

def get_logger(name="crypto_suite"):
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler("logs/security_audit.jsonl", encoding="utf-8")
        fh.setFormatter(JsonSecurityFormatter())
        logger.addHandler(fh)
    return logger
