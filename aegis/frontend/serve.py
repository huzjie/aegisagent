from __future__ import annotations
"""挂载前端静态文件到 API 服务器。"""
import http.server
import os
from pathlib import Path
from . import get_static_dir

class FrontendHandler(http.server.SimpleHTTPRequestHandler):
    """前端静态文件处理器。"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(get_static_dir()), **kwargs)
    
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()
