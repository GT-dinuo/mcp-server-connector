#!/bin/bash
# GitHub 发布脚本

echo "=== MCP Log Analyzer 发布脚本 ==="
echo ""

# 检查是否配置了远程仓库
if ! git remote get-url origin > /dev/null 2>&1; then
    echo "⚠️  未配置远程仓库"
    echo ""
    echo "请先在 GitHub 创建仓库，然后运行："
    echo "  git remote add origin https://github.com/YOUR_USERNAME/mcp-log-analyzer.git"
    echo ""
    read -p "输入你的 GitHub 用户名: " username
    read -p "输入仓库名称 (默认: mcp-log-analyzer): " reponame
    reponame=${reponame:-mcp-log-analyzer}

    git remote add origin "https://github.com/$username/$reponame.git"
    echo "✅ 远程仓库已添加"
fi

echo ""
echo "正在推送到 GitHub..."
git branch -M main
git push -u origin main

echo ""
if [ $? -eq 0 ]; then
    echo "✅ 推送成功！"
    echo ""
    echo "你的仓库地址:"
    git remote get-url origin
else
    echo "❌ 推送失败，请检查："
    echo "   1. 是否已在 GitHub 创建仓库"
    echo "   2. 是否有推送权限"
    echo "   3. 网络连接是否正常"
fi
