# 前言
不折腾甲骨文了，公布自用抢购脚本，不保证会更新，基于OCI命令编写终端交互安全系数更高。补一句：有问题请自行解决
# 脚本优缺点
- 交互式配置，支持ARM和AMD架构
- 自动后台运行，日志保存到log目录
- 智能重试机制，网络异常自动重试
- 自动创建虚拟云网络，VPC网络（非传统网络/基础网络）
- 自动开启IPV6
- 内存消耗80-110M

- 单账户，无Web
- 仅支持公私验证登录服务器
# OCI安装
一路回车 注意：要按 y <br>私钥为你API的私钥文件 （比如：1111@11111-2025-08-24T09_14_41.053Z.pem  不是public.pem）
```
bash -c "$(curl –L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)"
```
```
oci -v
```
配置cli账号信息，添加api key （不知道？百度或谷歌找教程）
```
oci setup config
```
修改OCI配置文件权限
```
chmod 600 /root/.oci/config
```
修改私钥文件权限 （我这以home为例）
```
chmod 600 /home/1111@11111-2025-08-24T09_14_41.053Z.pem
```
# 脚本安装
以yum系列linux演示，apt系列linux命令有点出入 安装依赖
```
yum install python3-pip -y && pip3 install oci && pip install requests && pip install prettytable
```
```
vi /home/api.conf
```
把以下内容保存到api.conf 脚本需要，key_file 为开机后需要的公钥，钉钉通知 webhook和secret请自行获取（不知道请百度或谷歌找教程）
```
[DEFAULT]
user = ocid1.user.oc1..aa
fingerprint = 4f:86:27:fa:e9:1f:90:bb:27
tenancy = ocid1.tenancy.oc1..aaaaaaaapfc7on7ljnylc2x5bpfj
region = ap-singapore-1
key_file = /home/ssh-key-2025-07-20.key.pub

# 钉钉通知
[DINGTALK]
webhook =
secret =
```
# 测试OCI
```
oci iam availability-domain list
```
# OCI 抢机脚本
```
wget https://raw.githubusercontent.com/kuke31/oci/main/seckill.py
```
# 使用方法
直接执行
```
python3 seckill.py
```
获取进程ID
```
ps aux | grep seckill.py
```
停止脚本
```
kill 123456 
```
或
```
pkill -f seckill.py
```
# 查看日志
```
tail -f log/arm_YYYY-MM-DD.log
```
或
```
tail -f log/amd_YYYY-MM-DD.log
```
# 效果图
![Design](https://github.com/kuke31/oci/blob/35ab8cfdd7dd804de71e3482474fa0b78977434e/img/2bc95c.png)
![ARM](https://github.com/kuke31/oci/blob/09611fc1d708503b9e205890cad526338f8fb2c9/img/a9abef3d-192c-49de-abb2-3b3b17680ef4.png)
![open](https://github.com/kuke31/oci/blob/5c2378a12aaba7c4671604311a25141377e100c5/img/69ddcfc6-f5c5-4e2e-b05d-c3aea8597e3a.png)
