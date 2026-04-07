#!/usr/bin/env python3
"""
MCP Server - 云服务器日志分析工具 (只读)
功能：连接云服务器，分析指定项目路径下的日志文件
安全限制：仅允许读取操作，禁止删除、修改、新增
"""

import json
import os
import re
import sys
from contextlib import closing
from dataclasses import dataclass
from typing import AsyncIterator, Sequence

import paramiko
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    LoggingLevel,
)
from pydantic import BaseModel, Field, validator


# ============ 配置模型 ============

class SSHConfig(BaseModel):
    """SSH 连接配置"""
    hostname: str = Field(description="服务器主机名或IP地址")
    port: int = Field(default=22, description="SSH端口")
    username: str = Field(description="SSH用户名")
    password: str | None = Field(default=None, description="SSH密码（与密钥二选一）")
    key_path: str | None = Field(default=None, description="SSH私钥路径")
    key_passphrase: str | None = Field(default=None, description="私钥密码")


class LogAnalysisConfig(BaseModel):
    """日志分析配置"""
    project_path: str = Field(description="项目路径")
    log_patterns: list[str] = Field(
        default=["*.log", "logs/**/*.log", "log/**/*.log"],
        description="日志文件匹配模式"
    )
    max_file_size: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        description="最大允许读取的文件大小（字节）"
    )
    max_lines: int = Field(
        default=10000,
        description="单次最大读取行数"
    )


# ============ SSH 连接管理器 ============

class SSHConnectionManager:
    """SSH连接管理器"""

    def __init__(self):
        self._client: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None

    def connect(self, config: SSHConfig) -> bool:
        """建立SSH连接"""
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": config.hostname,
                "port": config.port,
                "username": config.username,
                "timeout": 30,
            }

            if config.password:
                connect_kwargs["password"] = config.password
            elif config.key_path:
                key_path = os.path.expanduser(config.key_path)
                private_key = paramiko.RSAKey.from_private_key_file(
                    key_path, password=config.key_passphrase
                )
                connect_kwargs["pkey"] = private_key
            else:
                # 尝试使用 SSH Agent
                connect_kwargs["allow_agent"] = True
                connect_kwargs["look_for_keys"] = True

            self._client.connect(**connect_kwargs)
            self._sftp = self._client.open_sftp()
            return True
        except Exception as e:
            print(f"SSH连接失败: {e}", file=sys.stderr)
            return False

    def disconnect(self):
        """断开SSH连接"""
        if self._sftp:
            try:
                self._sftp.close()
            except:
                pass
            self._sftp = None
        if self._client:
            try:
                self._client.close()
            except:
                pass
            self._client = None

    @property
    def is_connected(self) -> bool:
        """检查连接状态"""
        if not self._client or not self._sftp:
            return False
        try:
            # 发送测试命令检查连接
            transport = self._client.get_transport()
            return transport is not None and transport.is_active()
        except:
            return False

    def execute_command(self, command: str) -> tuple[int, str, str]:
        """执行远程命令，返回 (exit_code, stdout, stderr)"""
        if not self._client:
            return -1, "", "未连接到服务器"

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=60)
            exit_code = stdout.channel.recv_exit_status()
            return exit_code, stdout.read().decode('utf-8', errors='replace'), stderr.read().decode('utf-8', errors='replace')
        except Exception as e:
            return -1, "", str(e)

    def read_file(self, remote_path: str, offset: int = 0, length: int = -1) -> bytes:
        """读取远程文件内容"""
        if not self._sftp:
            raise RuntimeError("未连接到服务器")

        # 安全检查：验证路径合法性
        self._validate_path(remote_path)

        with self._sftp.file(remote_path, 'rb') as f:
            if offset > 0:
                f.seek(offset)
            if length > 0:
                return f.read(length)
            return f.read()

    def list_directory(self, remote_path: str) -> list[dict]:
        """列出目录内容"""
        if not self._sftp:
            raise RuntimeError("未连接到服务器")

        self._validate_path(remote_path)

        entries = []
        for entry in self._sftp.listdir_attr(remote_path):
            entries.append({
                "name": entry.filename,
                "size": entry.st_size,
                "mode": entry.st_mode,
                "mtime": entry.st_mtime,
                "is_dir": entry.st_mode & 0o40000 == 0o40000,
                "is_file": entry.st_mode & 0o100000 == 0o100000,
            })
        return entries

    def get_file_info(self, remote_path: str) -> dict:
        """获取文件信息"""
        if not self._sftp:
            raise RuntimeError("未连接到服务器")

        self._validate_path(remote_path)

        try:
            stat = self._sftp.stat(remote_path)
            return {
                "exists": True,
                "size": stat.st_size,
                "mode": stat.st_mode,
                "mtime": stat.st_mtime,
                "is_dir": stat.st_mode & 0o40000 == 0o40000,
                "is_file": stat.st_mode & 0o100000 == 0o100000,
            }
        except FileNotFoundError:
            return {"exists": False}

    def _validate_path(self, path: str):
        """验证路径安全性 - 防止目录遍历攻击"""
        # 规范化路径
        normalized = os.path.normpath(path)

        # 禁止包含 .. 的路径遍历尝试
        if ".." in normalized.split(os.sep):
            raise ValueError(f"非法路径: 禁止目录遍历 ({path})")

        # 禁止访问系统敏感目录
        forbidden_patterns = [
            r'^/etc/passwd',
            r'^/etc/shadow',
            r'^/etc/ssh',
            r'^/root',
            r'^/proc',
            r'^/sys',
            r'^/dev',
            r'\.ssh',
            r'\.aws',
            r'\.docker',
        ]

        for pattern in forbidden_patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                raise ValueError(f"非法路径: 禁止访问系统敏感目录 ({path})")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# ============ MCP 服务器 ============

app = Server("mcp-log-analyzer")
ssh_manager = SSHConnectionManager()
current_config: dict = {}


# ============ 工具定义 ============

CONNECT_TOOL = Tool(
    name="connect_server",
    description="连接云服务器",
    inputSchema={
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "服务器主机名或IP地址"
            },
            "port": {
                "type": "integer",
                "description": "SSH端口（默认22）",
                "default": 22
            },
            "username": {
                "type": "string",
                "description": "SSH用户名"
            },
            "password": {
                "type": "string",
                "description": "SSH密码（可选，与密钥二选一）"
            },
            "key_path": {
                "type": "string",
                "description": "SSH私钥路径（可选）"
            }
        },
        "required": ["hostname", "username"]
    }
)

DISCONNECT_TOOL = Tool(
    name="disconnect_server",
    description="断开当前服务器连接",
    inputSchema={
        "type": "object",
        "properties": {}
    }
)

LIST_PROJECTS_TOOL = Tool(
    name="list_projects",
    description="列出指定路径下的项目目录",
    inputSchema={
        "type": "object",
        "properties": {
            "base_path": {
                "type": "string",
                "description": "基础路径（如 /var/www, /home/user/projects）",
                "default": "/home"
            }
        }
    }
)

FIND_LOGS_TOOL = Tool(
    name="find_logs",
    description="在项目路径下查找日志文件",
    inputSchema={
        "type": "object",
        "properties": {
            "project_path": {
                "type": "string",
                "description": "项目根路径"
            },
            "patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "日志文件匹配模式（如 ['*.log', 'logs/*.log']）",
                "default": ["*.log"]
            },
            "max_depth": {
                "type": "integer",
                "description": "最大搜索深度",
                "default": 5
            }
        },
        "required": ["project_path"]
    }
)

READ_LOG_TOOL = Tool(
    name="read_log",
    description="读取日志文件内容（只读）",
    inputSchema={
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "日志文件的完整路径"
            },
            "lines": {
                "type": "integer",
                "description": "读取的行数（从末尾开始，负数表示从头开始）",
                "default": 100
            },
            "offset": {
                "type": "integer",
                "description": "字节偏移量（与lines二选一）",
                "default": 0
            }
        },
        "required": ["file_path"]
    }
)

ANALYZE_LOG_TOOL = Tool(
    name="analyze_log",
    description="分析日志文件（错误统计、关键字提取等）",
    inputSchema={
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "日志文件的完整路径"
            },
            "analysis_type": {
                "type": "string",
                "enum": ["errors", "warnings", "keywords", "summary", "tail"],
                "description": "分析类型：errors(错误), warnings(警告), keywords(关键字), summary(摘要), tail(尾部)"
            },
            "keywords": {
                "type": "array",
                "items": {"type": "string"},
                "description": "自定义关键字列表（analysis_type=keywords时使用）",
                "default": []
            },
            "time_range": {
                "type": "string",
                "description": "时间范围过滤（如 '1h'最近1小时, '1d'最近1天）",
                "default": ""
            }
        },
        "required": ["file_path", "analysis_type"]
    }
)

SEARCH_LOGS_TOOL = Tool(
    name="search_logs",
    description="在多个日志文件中搜索关键字",
    inputSchema={
        "type": "object",
        "properties": {
            "project_path": {
                "type": "string",
                "description": "项目根路径"
            },
            "keyword": {
                "type": "string",
                "description": "搜索关键字"
            },
            "file_pattern": {
                "type": "string",
                "description": "文件匹配模式",
                "default": "*.log"
            },
            "case_sensitive": {
                "type": "boolean",
                "description": "区分大小写",
                "default": False
            }
        },
        "required": ["project_path", "keyword"]
    }
)

GET_LOG_SIZE_TOOL = Tool(
    name="get_log_size",
    description="获取日志文件大小和基本信息",
    inputSchema={
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "日志文件的完整路径"
            }
        },
        "required": ["file_path"]
    }
)


# ============ 工具处理 ============

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        CONNECT_TOOL,
        DISCONNECT_TOOL,
        LIST_PROJECTS_TOOL,
        FIND_LOGS_TOOL,
        READ_LOG_TOOL,
        ANALYZE_LOG_TOOL,
        SEARCH_LOGS_TOOL,
        GET_LOG_SIZE_TOOL,
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
    try:
        if name == "connect_server":
            return await handle_connect(arguments)
        elif name == "disconnect_server":
            return await handle_disconnect(arguments)
        elif name == "list_projects":
            return await handle_list_projects(arguments)
        elif name == "find_logs":
            return await handle_find_logs(arguments)
        elif name == "read_log":
            return await handle_read_log(arguments)
        elif name == "analyze_log":
            return await handle_analyze_log(arguments)
        elif name == "search_logs":
            return await handle_search_logs(arguments)
        elif name == "get_log_size":
            return await handle_get_log_size(arguments)
        else:
            return [TextContent(type="text", text=f"未知工具: {name}")]
    except Exception as e:
        return [TextContent(type="text", text=f"错误: {str(e)}")]


async def handle_connect(args: dict) -> list[TextContent]:
    """处理连接请求"""
    global current_config

    # 断开现有连接
    if ssh_manager.is_connected:
        ssh_manager.disconnect()

    config = SSHConfig(**args)

    if ssh_manager.connect(config):
        current_config = {
            "hostname": config.hostname,
            "port": config.port,
            "username": config.username,
        }
        return [TextContent(
            type="text",
            text=f"✅ 成功连接到服务器 {config.hostname}:{config.port} (用户: {config.username})"
        )]
    else:
        return [TextContent(
            type="text",
            text=f"❌ 连接失败: 无法连接到 {config.hostname}:{config.port}"
        )]


async def handle_disconnect(args: dict) -> list[TextContent]:
    """处理断开连接请求"""
    global current_config

    if ssh_manager.is_connected:
        hostname = current_config.get("hostname", "未知")
        ssh_manager.disconnect()
        current_config = {}
        return [TextContent(type="text", text=f"✅ 已断开与 {hostname} 的连接")]
    else:
        return [TextContent(type="text", text="ℹ️ 当前没有活动的连接")]


async def handle_list_projects(args: dict) -> list[TextContent]:
    """列出项目目录"""
    if not ssh_manager.is_connected:
        return [TextContent(type="text", text="❌ 错误: 未连接到服务器，请先使用 connect_server 连接")]

    base_path = args.get("base_path", "/home")

    try:
        entries = ssh_manager.list_directory(base_path)
        projects = [e for e in entries if e["is_dir"]]

        if not projects:
            return [TextContent(type="text", text=f"在 {base_path} 下未找到项目目录")]

        result = [f"📁 {base_path} 下的项目目录：\n"]
        for p in sorted(projects, key=lambda x: x["name"]):
            result.append(f"  📂 {p['name']}")

        return [TextContent(type="text", text="\n".join(result))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ 列出目录失败: {str(e)}")]


async def handle_find_logs(args: dict) -> list[TextContent]:
    """查找日志文件"""
    if not ssh_manager.is_connected:
        return [TextContent(type="text", text="❌ 错误: 未连接到服务器，请先使用 connect_server 连接")]

    project_path = args["project_path"]
    patterns = args.get("patterns", ["*.log"])
    max_depth = args.get("max_depth", 5)

    # 构建 find 命令（只读操作）
    find_commands = []
    for pattern in patterns:
        # 安全检查：转义特殊字符
        safe_pattern = pattern.replace("'", "'\"'\"'")
        cmd = f"find '{project_path}' -maxdepth {max_depth} -type f -name '{safe_pattern}' 2>/dev/null"
        find_commands.append(cmd)

    combined_cmd = " | ".join([f"({'cmd}')" for cmd in find_commands])
    cmd = f"{' ; '.join(find_commands)} | sort -u"

    exit_code, stdout, stderr = ssh_manager.execute_command(cmd)

    if exit_code != 0:
        return [TextContent(type="text", text=f"❌ 查找日志失败: {stderr}")]

    log_files = [line.strip() for line in stdout.strip().split('\n') if line.strip()]

    if not log_files:
        return [TextContent(type="text", text=f"在 {project_path} 下未找到匹配 {patterns} 的日志文件")]

    # 获取文件详情
    result = [f"📝 在 {project_path} 下找到 {len(log_files)} 个日志文件：\n"]

    for log_file in log_files[:50]:  # 限制显示数量
        try:
            info = ssh_manager.get_file_info(log_file)
            size_str = format_size(info.get("size", 0))
            result.append(f"  📄 {log_file} ({size_str})")
        except:
            result.append(f"  📄 {log_file}")

    if len(log_files) > 50:
        result.append(f"\n... 还有 {len(log_files) - 50} 个文件未显示")

    return [TextContent(type="text", text="\n".join(result))]


async def handle_read_log(args: dict) -> list[TextContent]:
    """读取日志文件"""
    if not ssh_manager.is_connected:
        return [TextContent(type="text", text="❌ 错误: 未连接到服务器，请先使用 connect_server 连接")]

    file_path = args["file_path"]
    lines = args.get("lines", 100)
    offset = args.get("offset", 0)

    try:
        # 获取文件信息
        info = ssh_manager.get_file_info(file_path)
        if not info.get("exists"):
            return [TextContent(type="text", text=f"❌ 文件不存在: {file_path}")]

        if info.get("is_dir"):
            return [TextContent(type="text", text=f"❌ 路径是目录，不是文件: {file_path}")]

        file_size = info.get("size", 0)
        max_size = 10 * 1024 * 1024  # 10MB 限制

        if file_size > max_size:
            return [TextContent(
                type="text",
                text=f"⚠️ 文件过大 ({format_size(file_size)})，将只读取最后 {format_size(max_size)}。使用 offset 参数可以读取其他部分。"
            )]

        # 使用 tail/head 命令读取（更高效的远程读取）
        if lines < 0:
            # 从头开始读取
            cmd = f"head -n {abs(lines)} '{file_path}' 2>/dev/null"
        else:
            # 从末尾读取
            cmd = f"tail -n {lines} '{file_path}' 2>/dev/null"

        exit_code, stdout, stderr = ssh_manager.execute_command(cmd)

        if exit_code != 0:
            return [TextContent(type="text", text=f"❌ 读取文件失败: {stderr}")]

        # 添加文件信息头
        header = f"📄 文件: {file_path}\n📏 大小: {format_size(file_size)}\n{'='*60}\n"

        return [TextContent(type="text", text=header + stdout)]

    except Exception as e:
        return [TextContent(type="text", text=f"❌ 读取文件失败: {str(e)}")]


async def handle_analyze_log(args: dict) -> list[TextContent]:
    """分析日志文件"""
    if not ssh_manager.is_connected:
        return [TextContent(type="text", text="❌ 错误: 未连接到服务器，请先使用 connect_server 连接")]

    file_path = args["file_path"]
    analysis_type = args["analysis_type"]
    keywords = args.get("keywords", [])
    time_range = args.get("time_range", "")

    # 获取文件信息
    info = ssh_manager.get_file_info(file_path)
    if not info.get("exists"):
        return [TextContent(type="text", text=f"❌ 文件不存在: {file_path}")]

    # 根据分析类型构建命令
    if analysis_type == "errors":
        # 统计错误
        cmd = f"grep -iE '(error|exception|fatal|failed)' '{file_path}' 2>/dev/null | tail -n 100"
        title = "❌ 错误分析"
    elif analysis_type == "warnings":
        # 统计警告
        cmd = f"grep -iE '(warn|warning|caution)' '{file_path}' 2>/dev/null | tail -n 100"
        title = "⚠️ 警告分析"
    elif analysis_type == "keywords":
        # 自定义关键字
        if not keywords:
            return [TextContent(type="text", text="❌ 请提供 keywords 参数")]
        pattern = "|".join(keywords)
        cmd = f"grep -iE '({pattern})' '{file_path}' 2>/dev/null | tail -n 100"
        title = f"🔍 关键字分析: {', '.join(keywords)}"
    elif analysis_type == "summary":
        # 摘要统计
        cmd = f"wc -l '{file_path}' && echo '---' && head -n 20 '{file_path}' 2>/dev/null"
        title = "📊 日志摘要"
    elif analysis_type == "tail":
        # 尾部内容
        cmd = f"tail -n 50 '{file_path}' 2>/dev/null"
        title = "📝 日志尾部"
    else:
        return [TextContent(type="text", text=f"❌ 未知的分析类型: {analysis_type}")]

    exit_code, stdout, stderr = ssh_manager.execute_command(cmd)

    if exit_code != 0:
        return [TextContent(type="text", text=f"❌ 分析失败: {stderr}")]

    result = [f"{title}\n📄 文件: {file_path}\n{'='*60}\n"]

    if not stdout.strip():
        result.append("未找到匹配的内容")
    else:
        result.append(stdout)

    return [TextContent(type="text", text="\n".join(result))]


async def handle_search_logs(args: dict) -> list[TextContent]:
    """在多个日志文件中搜索"""
    if not ssh_manager.is_connected:
        return [TextContent(type="text", text="❌ 错误: 未连接到服务器，请先使用 connect_server 连接")]

    project_path = args["project_path"]
    keyword = args["keyword"]
    file_pattern = args.get("file_pattern", "*.log")
    case_sensitive = args.get("case_sensitive", False)

    # 转义关键字中的特殊字符
    safe_keyword = keyword.replace("'", "'\"'\"'")
    safe_pattern = file_pattern.replace("'", "'\"'\"'")

    # 构建 grep 命令
    case_flag = "" if case_sensitive else "-i"
    cmd = f"find '{project_path}' -type f -name '{safe_pattern}' -exec grep -l {case_flag} '{safe_keyword}' {{}} + 2>/dev/null"

    exit_code, stdout, stderr = ssh_manager.execute_command(cmd)

    if exit_code != 0 and not stdout:
        return [TextContent(type="text", text=f"❌ 搜索失败: {stderr}")]

    matching_files = [line.strip() for line in stdout.strip().split('\n') if line.strip()]

    if not matching_files:
        return [TextContent(
            type="text",
            text=f"在 {project_path} 下未找到包含 '{keyword}' 的 {file_pattern} 文件"
        )]

    # 在匹配的文件中搜索具体行
    result = [f"🔍 搜索 '{keyword}' 的结果:\n找到 {len(matching_files)} 个匹配文件\n{'='*60}\n"]

    for match_file in matching_files[:10]:  # 限制显示文件数
        result.append(f"\n📄 {match_file}:")
        grep_cmd = f"grep -n {case_flag} '{safe_keyword}' '{match_file}' 2>/dev/null | head -n 10"
        _, content, _ = ssh_manager.execute_command(grep_cmd)
        for line in content.strip().split('\n'):
            if line:
                result.append(f"    {line}")

    if len(matching_files) > 10:
        result.append(f"\n... 还有 {len(matching_files) - 10} 个文件")

    return [TextContent(type="text", text="\n".join(result))]


async def handle_get_log_size(args: dict) -> list[TextContent]:
    """获取日志文件信息"""
    if not ssh_manager.is_connected:
        return [TextContent(type="text", text="❌ 错误: 未连接到服务器，请先使用 connect_server 连接")]

    file_path = args["file_path"]

    try:
        info = ssh_manager.get_file_info(file_path)
        if not info.get("exists"):
            return [TextContent(type="text", text=f"❌ 文件不存在: {file_path}")]

        # 获取额外统计信息
        cmd = f"wc -l '{file_path}' 2>/dev/null"
        exit_code, stdout, _ = ssh_manager.execute_command(cmd)

        line_count = "未知"
        if exit_code == 0:
            line_count = stdout.strip().split()[0]

        result = [
            f"📄 文件信息: {file_path}",
            f"{'='*60}",
            f"存在: ✅",
            f"类型: {'目录' if info['is_dir'] else '文件'}",
            f"大小: {format_size(info['size'])}",
            f"行数: {line_count}",
            f"修改时间: {info.get('mtime', '未知')}",
            f"权限: {oct(info.get('mode', 0))[-3:]}",
        ]

        return [TextContent(type="text", text="\n".join(result))]

    except Exception as e:
        return [TextContent(type="text", text=f"❌ 获取文件信息失败: {str(e)}")]


def format_size(size_bytes: int) -> str:
    """格式化文件大小"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


# ============ 主入口 ============

async def main():
    """MCP 服务器主入口"""
    async with stdio_server() as streams:
        await app.run(
            streams[0],
            streams[1],
            app.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
