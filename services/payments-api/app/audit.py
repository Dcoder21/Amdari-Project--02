"""Structured audit logging helpers."""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentinelpay.audit")
logging.basicConfig(level=logging.INFO)


def audit_log(event_type, actor_id=None, target=None, outcome="unknown", details=None):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "actor_id": actor_id,
        "target": target,
        "outcome": outcome,
        "details": details or {},
    }

    logger.info(json.dumps(event, default=str))