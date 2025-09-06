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
# 脚本安装

# oci
OCI 抢机脚本 - 钉钉通知版
