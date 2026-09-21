"""
Audit logging for the URL-infra-resolver.

Writes one record per lookup to the DynamoDB table 'csaa-url-resolver' in the
tooling account (344327960130). Uses the instance's own credentials (no
assume-role -- the table is local to the tooling account).

Design: FAIL SOFT. An audit-write failure must never break or delay the lookup
response to the user. All errors are logged and swallowed.
"""

from __future__ import annotations

import os
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

import boto3

logger = logging.getLogger("url-infra-resolver.audit")

AUDIT_TABLE = os.environ.get("RESOLVER_AUDIT_TABLE", "csaa-url-resolver")
AUDIT_REGION = os.environ.get("RESOLVER_AUDIT_REGION", "us-west-2")
# Audit records are retained INDEFINITELY -- no TTL / expiry.


class AuditLogger:
    def __init__(self, session: Optional[boto3.Session] = None,
                 table_name: str = AUDIT_TABLE,
                 region: str = AUDIT_REGION):
        self.table_name = table_name
        self.region = region
        try:
            sess = session or boto3.Session()
            self._table = sess.resource("dynamodb", region_name=region).Table(table_name)
        except Exception as e:  # noqa: BLE001
            logger.warning("Audit disabled: could not init DynamoDB client: %s", e)
            self._table = None

    def record(self, *, url: str, hostname: str, result: dict,
               requester: Optional[str] = None,
               source_ip: Optional[str] = None) -> Optional[str]:
        """Write one audit record. Returns the lookup_id, or None on failure.
        Never raises."""
        if self._table is None:
            return None

        lookup_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # Summarize the result compactly for the audit record.
        matches = result.get("matches", []) if isinstance(result, dict) else []
        zone_records = result.get("zone_records", []) if isinstance(result, dict) else []
        accounts = sorted({m.get("account_id") for m in matches if m.get("account_id")})
        resource_types = sorted({m.get("resource_type") for m in matches if m.get("resource_type")})
        resource_ids = [m.get("resource_id") for m in matches if m.get("resource_id")]
        alias_targets = [z.get("alias_target") for z in zone_records if z.get("alias_target")]

        item = {
            "lookup_id": lookup_id,
            "timestamp": now.isoformat(),
            "url": url or "",
            "hostname": hostname or "",
            "requester": requester or "unknown",
            "source_ip": source_ip or "unknown",
            "result_accounts": accounts or ["none"],
            "result_resource_types": resource_types or ["none"],
            "result_resource_ids": resource_ids or [],
            "result_alias_targets": alias_targets or [],
            "matched": bool(matches or zone_records),
        }

        try:
            self._table.put_item(Item=item)
            logger.info("Audit recorded lookup_id=%s hostname=%s requester=%s",
                        lookup_id, hostname, item["requester"])
            return lookup_id
        except Exception as e:  # noqa: BLE001 - fail soft
            logger.warning("Audit write failed (lookup still served): %s", e)
            return None
