# tencent-dnspod
腾讯DNSPOD命令行工具，使用python自动的argparse模块构建，目前仅实现了部分功能。本程序比较容易扩展，感兴趣的朋友可以自行添加需要的功能。
## 一、功能清单
1. 查询域名列表
2. 查询记录列表
可按记录类型类型（'A', 'CNAME', 'MX', 'TXT', 'NS', 'AAAA', 'SRV'）进行查询
3. 添加DNS记录
4. 删除DNS记录
5. 更新DNS记录

**使用方法详情请尝试使用python3 dnspod.py -h进行查看。由于本脚本使用了子命令，因此也可以在子命令后面添加-h参数来查看子命令的帮助。如："python3 dnspod.py domain query -h"、"python3 dnspod.py record add -h"**
## 二、使用方法
### 1. 创建配置文件
```json
{
    "secretId": "xxx",
    "secretKey": "xxx",
    "apiUrl": "https://cns.api.qcloud.com/v2/index.php"
}
```
需要把secretId与secretKey设置为你在腾讯云上的真实参数值。获取secretId与secretKey的具体菜单路径为“访问管理->访问密钥->API密钥管理”。

### 2. 安装依赖包
sudo pip3 install requests

### 3. 调用程序
python3 dnspod.py -C {配置文件路径} domain query list
