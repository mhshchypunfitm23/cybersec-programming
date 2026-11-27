import json, logging, time, os

LOG_PATH = os.environ.get('APP_LOG', 'server/logs/app.jsonl')
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

class JSONFormatter(logging.Formatter):
    def format(self, record):
        data = {"ts": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), "level": record.levelname, "msg": record.getMessage()}
        if hasattr(record, 'extra') and isinstance(record.extra, dict):
            data.update(record.extra)
        return json.dumps(data, ensure_ascii=False)

def get_logger():
    logger = logging.getLogger('app')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(LOG_PATH, encoding='utf-8')
        fh.setFormatter(JSONFormatter())
        logger.addHandler(fh)
    return logger
