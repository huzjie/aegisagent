from __future__ import annotations
"""手工维护的 OpenAPI 3.1 spec。"""
from typing import Any, Dict


def get_openapi_spec() -> Dict[str, Any]:
    """返回 OpenAPI 规范字典。"""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "AegisAgent API",
            "version": "0.1.0",
            "description": "AI Agent 运行时安全网关 HTTP API",
        },
        "paths": {
            "/healthz": {"get": {"summary": "存活探针", "responses": {"200": {"description": "OK"}}}},
            "/readyz": {"get": {"summary": "就绪探针", "responses": {"200": {"description": "OK"}}}},
            "/version": {"get": {"summary": "版本信息", "responses": {"200": {"description": "OK"}}}},
            "/v1/decisions/evaluate": {
                "post": {
                    "summary": "评估工具调用",
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    "responses": {"200": {"description": "决策结果"}},
                }
            },
            "/v1/audit/events": {"get": {"summary": "审计事件列表", "responses": {"200": {"description": "OK"}}}},
            "/v1/audit/stats": {"get": {"summary": "审计统计", "responses": {"200": {"description": "OK"}}}},
            "/v1/policy": {"get": {"summary": "获取策略", "responses": {"200": {"description": "OK"}}}},
            "/v1/tools": {"get": {"summary": "工具列表", "responses": {"200": {"description": "OK"}}}},
            "/v1/mcp/servers": {"get": {"summary": "MCP 服务器列表", "responses": {"200": {"description": "OK"}}}},
            "/v1/approvals": {"get": {"summary": "审批列表", "responses": {"200": {"description": "OK"}}}},
            "/v1/metrics": {"get": {"summary": "Prometheus 指标", "responses": {"200": {"description": "OK"}}}},
        },
    }
