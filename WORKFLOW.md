# ZhaoHub Git 协作开发工作流 (Git Workflow Guide)

为了保护 `main` 分支不被直接污染并确保代码质量，所有开发任务建议遵循以下**分支/合并/PR**流程。

## 1. 准备开发 (Start Work)
在开始任何功能开发或修复之前，请确保你的 `main` 分支是最新的。

```powershell
# 切换到 main 分支并拉取最新代码
git checkout main
git pull origin main
```

## 2. 创建特性分支 (New Branch)
从最新的 `main` 创建一个描述性的新分支。

```powershell
# 创建并切换到新分支 (例如: feature/ui-update)
git checkout -b feature/your-feature-name
```

## 3. 进行开发 (Development)
在本地编辑器中进行代码修改。

## 4. 提交更改 (Commit)
定期提交你的代码改动。

```powershell
# 查看修改的文件
git status

# 添加并提交
git add .
git commit -m "feat: 简短描述你的改动内容"
```

## 5. 同步与合并 (Sync & Merge)
在发布分支前，务必合并远程最新的 `main`代码到你的分支，以提前解决潜在冲突。

```powershell
# 获取远程最新代码
git fetch origin

# 合并远程 main 到当前分支
git merge origin/main
```
*如果出现冲突(Conflict)，请在 VS Code 中手动解决并再次 commit。*

## 6. 发布并创建 PR (Push & Pull Request)
将你的本地分支推送到 GitHub。

```powershell
# 发布分支到远程
git push -u origin feature/your-feature-name
```

**前往 GitHub 操作：**
1. 访问 [Zhaohub-Web GitHub Repo](https://github.com/lihuss/ZhaoHub-Web) (或根据推送终端返回的链接)。
2. 点击 **Compare & pull request**。
3. 检查代码差异，确认无误后点击 **Create pull request**。
4. 等待合并或由其他具有权限的人审核。

---

*GitHub Copilot 为 ZhaoHub 团队整理*
