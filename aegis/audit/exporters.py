"""Multi-format audit event exporters.

Supports JSONL, JSON array and CSV output.  The JSONL format is the canonical
storage format used by :class:`AuditLedger`; JSON and CSV are provided for
interchange with SIEM tools and spreadsheets.
"""

from __future__ import annotations

import csv
import io
import json
import os
from typing import IO, Any, Dict, Iterable, List, Optional, Sequence

from .event import AuditEventRecord, record_to_dict

__all__ = ["AuditExporter"]


class AuditExporter:
    """Export audit events to JSONL, JSON or CSV.

    The exporter is stateless; it simply iterates the supplied events and
    writes them to the requested destination.
    """

    SUPPORTED_FORMATS = ("jsonl", "json", "csv")

    def __init__(self) -> None:
        pass

    def export(
        self,
        events: Iterable[AuditEventRecord],
        fmt: str = "jsonl",
        path: str = "",
    ) -> str:
        """Write events to *path* (or return a string if *path* is empty).

        Args:
            events: iterable of :class:`AuditEventRecord` to export.
            fmt: output format — ``jsonl``, ``json`` or ``csv``.
            path: destination file path.  If empty, the output is returned as a
                string.

        Returns:
            The file path written to, or the string representation when *path*
            is empty.
        """
        fmt = (fmt or "jsonl").lower()
        if fmt not in self.SUPPORTED_FORMATS:
            raise ValueError(f"unsupported export format: {fmt!r}")
        events_list = list(events)
        if fmt == "jsonl":
            return self._export_jsonl(events_list, path)
        if fmt == "json":
            return self._export_json(events_list, path)
        return self._export_csv(events_list, path)

    def _export_jsonl(self, events: Sequence[AuditEventRecord], path: str) -> str:
        if path:
            _ensure_parent(path)
            with open(path, "w", encoding="utf-8") as fh:
                for event in events:
                    fh.write(event.to_json() + "\n")
            return path
        buf = io.StringIO()
        for event in events:
            buf.write(event.to_json() + "\n")
        return buf.getvalue()

    def _export_json(self, events: Sequence[AuditEventRecord], path: str) -> str:
        payload = [record_to_dict(e) for e in events]
        text = json.dumps(payload, ensure_ascii=False, default=str, indent=2)
        if path:
            _ensure_parent(path)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return path
        return text

    def _export_csv(self, events: Sequence[AuditEventRecord], path: str) -> str:
        columns = [
            "id", "sequence", "timestamp", "tenant_id", "actor",
            "action", "resource", "outcome", "severity",
            "session_id", "agent_id", "principal_id",
            "prev_hash", "hash", "signature",
        ]
        if path:
            _ensure_parent(path)
            fh = open(path, "w", encoding="utf-8", newline="")
        else:
            fh = io.StringIO(newline="")
        try:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for event in events:
                row = record_to_dict(event)
                row["severity"] = event.severity.value
                row["payload_json"] = json.dumps(event.payload, ensure_ascii=False, default=str)
                writer.writerow(row)
        finally:
            if path:
                fh.close()
        if path:
            return path
        assert isinstance(fh, io.StringIO)
        return fh.getvalue()


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
