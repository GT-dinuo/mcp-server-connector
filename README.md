# MCP Server Connector

一个用于连接云服务器并分析项目文件的 MCP (Model Context Protocol) 服务器。支持安全地浏览、查看和分析服务器上的项目内容。

## 功能特性

- 🔐 **安全的只读访问** - 仅允许读取操作，禁止删除、修改、新增
- 🔗 **SSH 连接** - 支持密码或密钥认证连接云服务器
- 📁 **项目管理** - 浏览项目目录结构
- 🔍 **日志搜索** - 按模式查找日志文件
- 📊 **日志分析** - 支持错误统计、警告提取、关键字搜索等
- 🛡️ **路径安全** - 防止目录遍历和访问敏感系统文件

## 安装

### 方式 1：使用 uv（推荐）

```bash
# 安装 uv（如未安装）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 克隆仓库
git clone https://github.com/GT-dinuo/mcp-server-connector.git
cd mcp-server-connector

# 使用 uv 运行
uv run server.py
```

### 方式 2：使用 pip

```bash
# 克隆仓库
git clone https://github.com/GT-dinuo/mcp-server-connector.git
cd mcp-server-connector

# 创建虚拟环境
python -m venv .venv

# 激活虚拟环境
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 方式 3：使用 Smithery

```bash
npx @smithery/cli install @gt-dinuo/mcp-server-connector
```

## 配置 Claude Desktop

在 Claude Desktop 配置文件 `claude_desktop_config.json` 中添加：

### Windows
```json
{
  "mcpServers": {
    "server-connector": {
      "command": "python",
      "args": ["C:\\path\\to\\mcp-server-connector\\server.py"]
    }
  }
}
```

### macOS/Linux
```json
{
  "mcpServers": {
    "server-connector": {
      "command": "python",
      "args": ["/path/to/mcp-server-connector/server.py"]
    }
  }
}
```

### 使用 uv（跨平台）
```json
{
  "mcpServers": {
    "server-connector": {
      "command": "uv",
      "args": ["--directory", "/path/to/mcp-server-connector", "run", "server.py"]
    }
  }
}
```

配置文件位置：
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

## 可用工具

### 1. connect_server - 连接服务器
```json
{
  "hostname": "your-server.com",
  "port": 22,
  "username": "root",
  "password": "your-password",
  "key_path": "/path/to/private/key"
}
```

### 2. disconnect_server - 断开连接
无需参数

### 3. list_projects - 列出项目
```json
{
  "base_path": "/home"
}
```

### 4. find_logs - 查找日志文件
```json
{
  "project_path": "/var/www/myapp",
  "patterns": ["*.log", "logs/**/*.log"],
  "max_depth": 5
}
```

### 5. read_log - 读取日志内容
```json
{
  "file_path": "/var/www/myapp/logs/app.log",
  "lines": 100
}
```

### 6. analyze_log - 分析日志
```json
{
  "file_path": "/var/www/myapp/logs/app.log",
  "analysis_type": "errors",
  "keywords": ["database", "timeout"]
}
```
分析类型: `errors`, `warnings`, `keywords`, `summary`, `tail`

### 7. search_logs - 搜索日志
```json
{
  "project_path": "/var/www/myapp",
  "keyword": "error",
  "file_pattern": "*.log"
}
```

### 8. get_log_size - 获取日志信息
```json
{
  "file_path": "/var/www/myapp/logs/app.log"
}
```

## 使用示例

1. **连接到服务器**
   - 使用 connect_server 工具建立 SSH 连接

2. **浏览项目**
   - 使用 list_projects 查看可用的项目目录

3. **查找日志**
   - 使用 find_logs 定位日志文件位置

4. **分析日志**
   - 使用 analyze_log 分析错误和警告
   - 使用 search_logs 搜索特定关键字
   - 使用 read_log 查看详细内容

5. **断开连接**
   - 使用 disconnect_server 安全断开

## 安全说明

- ⚠️ 仅允许读取操作，所有修改操作均被禁止
- 🔒 禁止访问系统敏感目录（/etc, /root, /proc 等）
- 🛡️ 内置路径验证防止目录遍历攻击
- 📏 单次读取文件大小限制为 10MB

## 依赖

- Python >= 3.10
- mcp >= 1.0.0
- paramiko >= 3.0.0
- pydantic >= 2.0.0

## 许可证

MIT
