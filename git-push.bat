@echo off
cd /d "d:\ai\trae\模拟宗门\XianxiaSect\server"
git add .
git commit -m "Initial commit - TapTap auth server"
git remote add origin https://github.com/hsmy7/xianxia-auth-server.git
git branch -M main
git push -u origin main
pause
