### git使用：

##### 设置用户信息

```git
 git config  --global user.name "chahaha"
 git config --global user.email "1259214791@qq.com"
```

##### 查看配置信息

```
git config --list
git config user.name
```

##### 分支创建删除切换

```
git checkout -b <branch>			创建一个<branch>分支，并切换到<branch>这个分支
git checkout <branch>				切换到<branch>分支
git branch -d <branch>				删除<branch>分支
git push origin <branch>			推送<branch>分支
```

##### 分支更新与合并

```
git pull									 更新本地仓库到最新改动
git merge <branch>							  合并<branch>到当前分支
git diff <source_branch> <target_barnch>		预览两个分支的差异
```

##### 代码提交（包含本地暂存）

```
git status   						 查看工作区代码相对于暂存区的差别
git add . 							 将当前目录下修改的所有代码从工作区添加到暂存区 . 代表当前目录
git commit -m ‘注释’     				将缓存区内容添加到本地仓库
git pull origin <branch>(远程) 		 先将远程仓库<branch>中的信息同步到本地<branch>中
git push origin <branch>(本地) 		 将本地<branch>推送到远程服务器<branch>中
		git push <远程主机名> <本地分支名>:<远程分支名> 
```

##### 仓库创建与分支管理

```
git init <dir>      		初始化目录
git clone <url>			    直接拷贝某个项目
git branch				    查看分支 
```
