#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCI 抢机脚本 - 钉钉通知版

使用方法:
- 直接运行: python3 seckill.py

脚本特点:
- 交互式配置，支持ARM和AMD架构
- 自动后台运行，日志保存到log目录
- 智能重试机制，网络异常自动重试

查看日志:
- 实时日志: tail -f log/arm_YYYY-MM-DD.log 或 log/amd_YYYY-MM-DD.log
- 获取进程ID: ps aux | grep seckill.py
- 停止脚本: kill id 或 pkill -f seckill.py
"""

import argparse, configparser, json, subprocess, oci, sys, time, random, os, requests, hmac, hashlib, base64, urllib.parse
from datetime import datetime
from typing import Optional, Tuple, Dict, Any, Union
from dataclasses import dataclass
from contextlib import contextmanager

# ==================== 配置常量 ====================
CONFIG_FILE = "api.conf"          # 配置文件路径
LOG_DIR = "log"                   # 日志目录
DEFAULT_TIMEOUT = 10              # 默认请求超时时间（秒）

# ==================== 文件常量 ====================
NSG_RULES_FILE = 'ssh-nsg-rules.json'       # NSG规则临时文件

# ==================== 网络异常关键词 ====================
TRANSIENT_ERROR_MARKERS = {
    "Remote end closed connection without response",
    "Connection aborted", 
    "Read timed out",
    "Max retries exceeded",
    "temporarily unavailable",
    "Temporary failure in name resolution",
    "Connection reset by peer"
}

# ==================== 架构配置 ====================
ARCH_CONFIGS = {
    "arm": {
        "shape": "VM.Standard.A1.Flex",     # ARM弹性实例
        "ocpu_range": (1, 4),               # OCPU范围：1-4核
        "memory_range": (1, 24),            # 内存范围：1-24GB
        "default_ocpu": 1,                  # 默认OCPU：1核
        "default_memory": 6                 # 默认内存：6GB
    },
    "amd": {
        "shape": "VM.Standard.E2.1.Micro",  # AMD微型实例
        "ocpu_range": (1, 1),               # OCPU范围：1核（固定）
        "memory_range": (1, 1),             # 内存范围：1GB（固定）
        "default_ocpu": 1,                  # 默认OCPU：1核
        "default_memory": 1                 # 默认内存：1GB
    }
}

@dataclass
class InstanceConfig:
    """实例配置类"""
    machine_type: str
    shape: str
    ocpus: int
    memory_gb: int
    image_name: str

@dataclass
class UserConfig:
    """用户配置类"""
    arch: str
    ocpus: int
    memory: int
    disk_size: int
    vpus: int
    interval: Union[int, str]

class BaseManager:
    """基础管理器类"""
    
    def __init__(self, config: configparser.ConfigParser, compartment_id: str):
        self.config = config
        self.compartment_id = compartment_id
    
    def _log(self, msg: str, logger=None):
        """统一日志输出"""
        if logger:
            logger.log(msg)
        else:
            print(msg)
    
    def _run_cli(self, cmd: list) -> Dict[str, Any]:
        """运行 oci CLI 并返回 JSON"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if not result.stdout.strip():
                return {"data": []}
            
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"data": []}
                
        except (subprocess.CalledProcessError, Exception):
            return {"data": []}
    
    def _run_cli_with_validation(self, cmd: list, resource_name: str, logger=None) -> Dict[str, Any]:
        """运行CLI命令并进行结果验证"""
        try:
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() or "未知错误"
                stdout_msg = result.stdout.strip() or "无输出"
                
                raise Exception(f"{resource_name}创建失败: {error_msg}")
            
            if not result.stdout.strip():
                raise Exception(f"{resource_name}创建失败：命令返回空输出")
            
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise Exception(f"{resource_name}创建失败：JSON解析错误 - {e}")
            
        except subprocess.TimeoutExpired:
            raise Exception(f"{resource_name}创建失败：命令执行超时")
        except Exception as e:
            if not isinstance(e, Exception):
                self._log(f"❌ 创建{resource_name}失败: {e}", logger)
            raise
    
    def _validate_response_data(self, data: Dict[str, Any], resource_name: str, logger=None) -> str:
        """验证响应数据并返回资源ID"""
        if isinstance(data, dict) and 'data' in data:
            resource_data = data['data']
            if isinstance(resource_data, dict) and 'id' in resource_data:
                return resource_data['id']
            else:
                raise Exception(f"创建{resource_name}失败：返回数据格式错误: {resource_data}")
        else:
            raise Exception(f"创建{resource_name}失败：返回数据格式错误: {data}")

class DingTalkNotifier(BaseManager):
    """钉钉通知器"""
    
    def __init__(self, config: configparser.ConfigParser):
        # 由于DingTalkNotifier不需要compartment_id，我们传入一个空字符串
        super().__init__(config, "")
        self._init_dingtalk_config()
    
    def _init_dingtalk_config(self):
        """初始化钉钉配置"""
        try:
            if "DINGTALK" in self.config:
                self.webhook = self.config["DINGTALK"].get("webhook", "").strip()
                self.secret = self.config["DINGTALK"].get("secret", "").strip()
            else:
                self.webhook = ""
                self.secret = ""
        except Exception:
            self.webhook = ""
            self.secret = ""
    
    def _calculate_signature(self, timestamp: str) -> str:
        """计算钉钉签名"""
        string_to_sign = f'{timestamp}\n{self.secret}'
        hmac_code = hmac.new(
            self.secret.encode('utf-8'), 
            string_to_sign.encode('utf-8'), 
            digestmod=hashlib.sha256
        ).digest()
        return urllib.parse.quote_plus(base64.b64encode(hmac_code))
    
    def send_notification(self, title: str, content: str, msg_type: str = "text", logger=None) -> bool:
        """
        发送钉钉通知
        
        Args:
            title: 通知标题
            content: 通知内容
            msg_type: 消息类型，默认为 text
            logger: 日志记录器实例
            
        Returns:
            bool: 发送是否成功
        """
        try:
            if not self.webhook or not self.secret:
                self._log("⚠️ 钉钉配置缺失，跳过通知发送", logger)
                return False

            timestamp = str(round(time.time() * 1000))
            sign = self._calculate_signature(timestamp)
            url = f"{self.webhook}&timestamp={timestamp}&sign={sign}"
            message = self._build_message(title, content, msg_type)
            headers = {'Content-Type': 'application/json'}
            response = requests.post(
                url, 
                headers=headers, 
                data=json.dumps(message), 
                timeout=DEFAULT_TIMEOUT
            )
            
            return self._handle_response(response, title, logger)
            
        except Exception as e:
            self._log(f"❌ 钉钉通知发送异常: {e}", logger)
            return False
    
    def _build_message(self, title: str, content: str, msg_type: str) -> Dict[str, Any]:
        """消息内容"""
        if msg_type == "text":
            return {
                "msgtype": "text",
                "text": {"content": f"{title}\n\n{content}"}
            }
        else:
            return {
                "msgtype": "markdown",
                "markdown": {"title": title, "text": content}
            }
    
    def _handle_response(self, response: requests.Response, title: str, logger=None) -> bool:
        """处理响应结果"""
        if response.status_code == 200:
            result = response.json()
            if result.get("errcode") == 0:
                self._log(f"✅ 钉钉通知发送成功: {title}", logger)
                return True
            else:
                self._log(f"❌ 钉钉通知发送失败: {result.get('errmsg', '未知错误')}", logger)
                return False
        else:
            self._log(f"❌ 钉钉通知请求失败，状态码: {response.status_code}", logger)
            return False

class Logger:
    """日志管理器"""
    
    def __init__(self, arch: str):
        self.arch = arch
        self.log_dir = LOG_DIR
        self.last_log_date = datetime.now().strftime("%Y-%m-%d")
        self._setup_log_file()
    
    def _setup_log_file(self):
        """设置日志文件"""
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = self._get_log_file()
        self.log_f = open(self.log_file, "a", encoding="utf-8")
    
    def _get_log_file(self) -> str:
        """获取日志文件路径"""
        today_str = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"{self.arch}_{today_str}.log")
    
    def log(self, msg: str):
        """记录日志"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        
        # 日期变更，切换日志文件
        if current_date != self.last_log_date:
            self._switch_log_file(current_date)
        
        print(msg)
        print(msg, file=self.log_f, flush=True)
    
    def _switch_log_file(self, new_date: str):
        """切换日志文件"""
        self.log_f.close()
        self.last_log_date = new_date
        self.log_file = self._get_log_file()
        self.log_f = open(self.log_file, "a", encoding="utf-8")
    
    def close(self):
        """关闭日志文件"""
        if hasattr(self, 'log_f'):
            self.log_f.close()

class NetworkManager(BaseManager):
    """网络资源管理器：确保 VCN、子网、网关、路由表、NSG 存在并保存到配置"""

    def _region_base_name(self) -> str:
        """从配置中解析 region 的中间部分，例如 ap-singapore-1 -> singapore"""
        region = self.config['DEFAULT'].get('region', '').strip().lower()
        if not region:
            return 'default'
        parts = region.split('-')
        if len(parts) >= 3:
            middle = '-'.join(parts[1:-1])
            return middle or region
        if len(parts) == 2:
            return parts[1]
        return region

    def get_existing_nsgs(self, vcn_id: str) -> list:
        """获取VCN现有网络安全组列表"""
        try:
            data = self._run_cli([
                'oci', 'network', 'nsg', 'list',
                '--compartment-id', self.compartment_id,
                '--vcn-id', vcn_id,
                '--all', '--output', 'json'
            ])
            return data.get('data', [])
        except Exception as e:
            self._log(f"获取网络安全组列表失败: {e}")
            return []

    def create_default_nsg(self, vcn_id: str, logger=None) -> str:
        """创建默认网络安全组"""
        nsg_display = str(int(time.time() * 1000))
        
        self._log("创建默认网络安全组...", logger)
        created_nsg = self._run_cli([
            'oci', 'network', 'nsg', 'create',
            '--compartment-id', self.compartment_id,
            '--vcn-id', vcn_id,
            '--display-name', nsg_display,
            '--output', 'json'
        ])['data']
        nsg_id = created_nsg['id']

        self._add_nsg_rules(nsg_id, logger)
        
        self._log(f"✅ 已创建默认网络安全组: {nsg_display}", logger)
        return nsg_id

    def _add_nsg_rules(self, nsg_id: str, logger=None):
        """添加NSG规则"""
        rules_payload = [
            # IPv4 SSH
            {"direction": "INGRESS", "protocol": "6", "source": "10.0.0.0/24", "sourceType": "CIDR_BLOCK"},
            {"direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "sourceType": "CIDR_BLOCK", "tcpOptions": {"destinationPortRange": {"max": 22, "min": 22}}},
            # ping
            {"direction": "INGRESS", "protocol": "1", "source": "0.0.0.0/0", "sourceType": "CIDR_BLOCK"},
            # IPv6 SSH
            {"direction": "INGRESS", "protocol": "6", "source": "::/0", "sourceType": "CIDR_BLOCK", "tcpOptions": {"destinationPortRange": {"max": 22, "min": 22}}},
            # IPv6 ping
            {"direction": "INGRESS", "protocol": "58", "source": "::/0", "sourceType": "CIDR_BLOCK", "icmpOptions": {"type": 128, "code": 0}}
        ]
        
        try:
            with open(NSG_RULES_FILE, 'w', encoding='utf-8') as f:
                json.dump(rules_payload, f)
            self._run_cli([
                'oci', 'network', 'nsg', 'rules', 'add',
                '--nsg-id', nsg_id,
                '--security-rules', f'file://{NSG_RULES_FILE}',
                '--output', 'json'
            ])
        finally:
            try:
                os.remove(NSG_RULES_FILE)
            except Exception:
                pass

    def configure_security_list_rules(self, vcn_id: str, logger=None):
        """智能配置安全列表规则，只在必要时执行"""
        try:
            # 检查是否已经配置过安全列表规则
            if self._is_security_list_configured(vcn_id):
                self._log("✅ 安全列表规则已配置，跳过配置操作", logger)
                return
            
            self._log("正在配置安全列表规则...", logger)
            
            # 获取VCN所有安全列表
            security_lists = self._run_cli([
                'oci', 'network', 'security-list', 'list',
                '--compartment-id', self.compartment_id,
                '--vcn-id', vcn_id,
                '--all', '--output', 'json'
            ])
            
            configured_count = 0
            for security_list in security_lists.get('data', []):
                security_list_id = security_list['id']
                security_list_name = security_list.get('display-name', 'Unknown')
                
                # 检查当前入站规则
                current_rules = self._run_cli([
                    'oci', 'network', 'security-list', 'get',
                    '--security-list-id', security_list_id,
                    '--output', 'json'
                ])
                
                ingress_rules = current_rules.get('data', {}).get('ingress-security-rules', [])
                
                # 入站规则不为空且不是我们配置的规则时才清空
                if ingress_rules and not self._is_our_configured_rules(ingress_rules):
                    self._log(f"📝 清空安全列表 '{security_list_name}' 旧入站规则", logger)
                    
                    # 清空入站规则
                    self._run_cli([
                        'oci', 'network', 'security-list', 'update',
                        '--security-list-id', security_list_id,
                        '--ingress-security-rules', '[]',
                        '--force',
                        '--output', 'json'
                    ])
                else:
                    self._log(f"✅ 安全列表 '{security_list_name}' 入站规则已正确配置", logger)
                
                # 检查并补充出站规则
                self._check_and_add_egress_rules(security_list_id, security_list_name, logger)
                
                configured_count += 1
            
            if configured_count > 0:
                self._log(f"✅ 成功配置 {configured_count} 个安全列表规则", logger)
                # 标记安全列表已配置
                self._mark_security_list_configured(vcn_id)
            else:
                self._log("⚠️ 未找到需要配置的安全列表", logger)
                
        except Exception as e:
            self._log(f"❌ 配置安全列表规则失败: {e}", logger)

    def _check_and_add_egress_rules(self, security_list_id: str, security_list_name: str, logger=None):
        """检查并添加出站规则"""
        try:
            # 获取当前出站规则
            current_rules = self._run_cli([
                'oci', 'network', 'security-list', 'get',
                '--security-list-id', security_list_id,
                '--output', 'json'
            ])
            
            egress_rules = current_rules.get('data', {}).get('egress-security-rules', [])
            
            # 规则检查
            destinations = [rule.get('destination', '') for rule in egress_rules]
            has_ipv4_rule = '0.0.0.0/0' in destinations
            has_ipv6_rule = '::/0' in destinations
                
            # 添加规则
            rules_to_add = [
                {
                    "destination": "0.0.0.0/0",
                    "destinationType": "CIDR_BLOCK",
                    "protocol": "all",
                    "isStateless": False
                } if not has_ipv4_rule else None,
                {
                    "destination": "::/0",
                    "destinationType": "CIDR_BLOCK",
                    "protocol": "all",
                    "isStateless": False
                } if not has_ipv6_rule else None
            ]
            
            # 过滤掉None值
            rules_to_add = [rule for rule in rules_to_add if rule is not None]
            
            # 记录需要添加的规则
            if not has_ipv4_rule:
                self._log(f"📝 需要添加 IPv4 出站规则到 '{security_list_name}'", logger)
            if not has_ipv6_rule:
                self._log(f"📝 需要添加 IPv6 出站规则到 '{security_list_name}'", logger)
                
            # 添加规则
            if rules_to_add:
                # 合并现有规则和新规则
                all_rules = egress_rules + rules_to_add
                
                # 更新出站规则
                self._run_cli([
                    'oci', 'network', 'security-list', 'update',
                    '--security-list-id', security_list_id,
                    '--egress-security-rules', json.dumps(all_rules),
                    '--force',
                    '--output', 'json'
                ])
                
                self._log(f"✅ 已为安全列表 '{security_list_name}' 添加出站规则", logger)
            else:
                self._log(f"✅ 安全列表 '{security_list_name}' 已放行IPv4/IPv6", logger)
                
        except Exception as e:
            self._log(f"❌ 检查出站规则失败: {e}", logger)
    
    def _is_security_list_configured(self, vcn_id: str) -> bool:
        """检查安全列表是否已配置"""
        try:
            # 检查配置文件中是否标记了该VCN的安全列表已配置
            configured_vcn = self.config['DEFAULT'].get('security_list_configured', '').strip()
            return configured_vcn == vcn_id
        except Exception:
            return False
    
    def _mark_security_list_configured(self, vcn_id: str):
        """标记安全列表已配置"""
        try:
            self.config['DEFAULT']['security_list_configured'] = vcn_id
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                self.config.write(f)
        except Exception as e:
            self._log(f"⚠️ 标记安全列表配置状态失败: {e}")
    
    def _is_our_configured_rules(self, rules: list) -> bool:
        """检查规则是否是我们配置的规则"""
        if not rules:
            return True
        return False

    def ensure_network(self, logger=None) -> Dict[str, str]:
        """检查/创建 VCN、子网、网关、路由/NSG，并返回关键ID"""
        self._log("正在检查网络资源...", logger)
        
        # 读取已有配置
        net_config = self._get_network_config()
        base = self._region_base_name()
        
        # 验证现有网络资源是否存在
        if self._validate_existing_resources(net_config, logger):
            self._log("✅ 已全部验证通过，无需更改配置", logger)
            self._save_network_config(net_config)
            return net_config
        else:
            self._log("❌ 本地配置验证失败，尝试查询远程现有资源...", logger)
            
            # 查询远程现有资源
            remote_net_config = self._query_remote_existing_resources(logger)
            if remote_net_config:
                self._log("✅ 发现远程现有网络资源，使用远程配置", logger)
                self._save_network_config(remote_net_config)
                return remote_net_config
            else:
                self._log("❌ 未发现远程现有资源，清空配置并重新创建", logger)
                self._clear_network_config()
                net_config = self._get_network_config()  # 重新获取清空后的配置
        
        # 检查 VCN
        vcn_id, created_vcn = self._ensure_vcn(net_config, base, logger)
        
        # 新建 VCN 创建其余资源
        self._create_network_resources(vcn_id, net_config, base, logger)
        self._save_network_config(net_config)
        
        self._log("已配齐 VCN 资源，网络资源检查完成。", logger)
        return net_config

    def _get_network_config(self) -> Dict[str, str]:
        """获取网络配置"""
        return {
            'vcn_id': self.config['DEFAULT'].get('vcn_id', '').strip(),
            'vcn_name': self.config['DEFAULT'].get('vcn_name', '').strip(),
            'subnet_id': self.config['DEFAULT'].get('subnet_id', '').strip(),
            'internet_gateway_id': self.config['DEFAULT'].get('internet_gateway_id', '').strip(),
            'route_table_id': self.config['DEFAULT'].get('route_table_id', '').strip(),
            'nsg_id': self.config['DEFAULT'].get('nsg_id', '').strip()
        }
    
    def _validate_existing_resources(self, net_config: Dict[str, str], logger=None) -> bool:
        """验证现有网络资源是否在OCI中存在"""
        self._log("正在验证现有网络资源...", logger)
        
        # 资源检查
        has_any_resource = any([
            net_config['vcn_id'],
            net_config['subnet_id'],
            net_config['internet_gateway_id'],
            net_config['route_table_id']
        ])
        
        if not has_any_resource:
            self._log("未检测到任何网络资源ID，需要重新创建", logger)
            return False
        
        # 验证VCN是否存在
        if net_config['vcn_id']:
            if not self._validate_vcn_exists(net_config['vcn_id'], logger):
                return False
        
        # 验证子网是否存在
        if net_config['subnet_id']:
            if not self._validate_subnet_exists(net_config['subnet_id'], logger):
                return False
        
        # 验证网关是否存在
        if net_config['internet_gateway_id']:
            if not self._validate_igw_exists(net_config['internet_gateway_id'], logger):
                return False
        
        # 验证路由表是否存在
        if net_config['route_table_id']:
            if not self._validate_route_table_exists(net_config['route_table_id'], logger):
                return False
        
        return True
    
    def _validate_resource_exists(self, resource_type: str, resource_id: str, cli_cmd: list, logger=None) -> bool:
        """通用资源验证方法"""
        try:
            data = self._run_cli(cli_cmd)
            if data.get('data', {}).get('id') == resource_id:
                self._log(f"✅ {resource_type}验证通过", logger)
                return True
            else:
                self._log(f"❌ {resource_type}验证失败: {resource_id}", logger)
                return False
        except Exception as e:
            self._log(f"❌ {resource_type}验证异常: {resource_id} - {e}", logger)
            return False
    
    def _validate_vcn_exists(self, vcn_id: str, logger=None) -> bool:
        """验证VCN是否存在"""
        return self._validate_resource_exists("VCN", vcn_id, [
            'oci', 'network', 'vcn', 'get',
            '--vcn-id', vcn_id,
            '--output', 'json'
        ], logger)
    
    def _validate_subnet_exists(self, subnet_id: str, logger=None) -> bool:
        """验证子网是否存在"""
        return self._validate_resource_exists("子网", subnet_id, [
            'oci', 'network', 'subnet', 'get',
            '--subnet-id', subnet_id,
            '--output', 'json'
        ], logger)
    
    def _validate_igw_exists(self, igw_id: str, logger=None) -> bool:
        """验证网关是否存在"""
        return self._validate_resource_exists("网关", igw_id, [
            'oci', 'network', 'internet-gateway', 'get',
            '--ig-id', igw_id,
            '--output', 'json'
        ], logger)
    
    def _validate_route_table_exists(self, route_table_id: str, logger=None) -> bool:
        """验证路由表是否存在"""
        return self._validate_resource_exists("路由表", route_table_id, [
            'oci', 'network', 'route-table', 'get',
            '--rt-id', route_table_id,
            '--output', 'json'
        ], logger)
    
    def _clear_network_config(self):
        """清空网络资源配置"""
        network_keys = [
            'vcn_id', 'vcn_name', 'subnet_id', 'internet_gateway_id', 
            'route_table_id', 'availability_domain'
        ]
        
        cleared_keys = [key for key in network_keys if key in self.config['DEFAULT']]
        for key in cleared_keys:
            del self.config['DEFAULT'][key]
        cleared_count = len(cleared_keys)
        
        if cleared_count > 0:
            # 保存清空后的配置
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                self.config.write(f)
            print(f"✅ 已清空 {cleared_count} 个网络资源配置项")
        else:
            print("✅ 无需清空网络资源配置")

    def _query_remote_existing_resources(self, logger=None) -> Optional[Dict[str, str]]:
        """查询OCI现有网络资源"""
        self._log("正在查询远程现有网络资源...", logger)
        
        try:
            # 查询现有VCN
            vcns = self._run_cli([
                'oci', 'network', 'vcn', 'list',
                '--compartment-id', self.compartment_id,
                '--all', '--output', 'json'
            ])
            
            if not vcns.get('data'):
                self._log("远程未发现VCN", logger)
                return None
            
            # 使用第一个VCN
            vcn = vcns['data'][0]
            vcn_id = vcn.get('id', '')
            vcn_name = vcn.get('display-name', '')
            
            if not vcn_id:
                self._log("VCN ID获取失败", logger)
                return None
            
            self._log(f"发现远程VCN: {vcn_name}", logger)
            
            # 查询该VCN下的子网
            subnets = self._run_cli([
                'oci', 'network', 'subnet', 'list',
                '--compartment-id', self.compartment_id,
                '--vcn-id', vcn_id,
                '--all', '--output', 'json'
            ])
            
            subnet_id = ""
            if subnets.get('data'):
                subnet = subnets['data'][0]
                subnet_id = subnet.get('id', '')
                self._log(f"发现远程子网: {subnet.get('display-name', 'Unknown')}", logger)
            
            # 查询该VCN的网关
            igws = self._run_cli([
                'oci', 'network', 'internet-gateway', 'list',
                '--compartment-id', self.compartment_id,
                '--vcn-id', vcn_id,
                '--all', '--output', 'json'
            ])
            
            igw_id = ""
            if igws.get('data'):
                igw = igws['data'][0]
                igw_id = igw.get('id', '')
                self._log(f"发现网关: {igw.get('display-name', 'Unknown')}", logger)
            
            # 查询该VCN下的路由表
            route_tables = self._run_cli([
                'oci', 'network', 'route-table', 'list',
                '--compartment-id', self.compartment_id,
                '--vcn-id', vcn_id,
                '--all', '--output', 'json'
            ])
            
            route_table_id = ""
            if route_tables.get('data'):
                route_table = route_tables['data'][0]
                route_table_id = route_table.get('id', '')
                self._log(f"发现路由表: {route_table.get('display-name', 'Unknown')}", logger)
            
            # 查询可用性域
            availability_domains = self._run_cli([
                'oci', 'iam', 'availability-domain', 'list',
                '--compartment-id', self.compartment_id,
                '--output', 'json'
            ])
            
            availability_domain = ""
            if availability_domains.get('data'):
                availability_domain = availability_domains['data'][0].get('name', '')
                self._log(f"发现可用性域: {availability_domain}", logger)
            
            # 网络配置
            remote_net_config = {
                'vcn_id': vcn_id,
                'vcn_name': vcn_name,
                'subnet_id': subnet_id,
                'internet_gateway_id': igw_id,
                'route_table_id': route_table_id,
                'availability_domain': availability_domain,
                'nsg_id': ''
            }
            
            self._log("✅ 远程网络资源查询完成", logger)
            return remote_net_config
            
        except Exception as e:
            self._log(f"❌ 查询远程网络资源失败: {e}", logger)
            return None

    def _ensure_vcn(self, net_config: Dict[str, str], base: str, logger=None) -> Tuple[str, bool]:
        """确保VCN存在"""
        self._log("正在创建新的VCN...", logger)
        
        # 创建新VCN
        vcn_display = f"{base}"
        self._log(f"正在创建VCN: {vcn_display} (启用IPv6)...", logger)
        
        try:
            created = self._run_cli([
                'oci', 'network', 'vcn', 'create',
                '--compartment-id', self.compartment_id,
                '--cidr-block', '10.0.0.0/16',
                '--display-name', vcn_display,
                '--is-ipv6-enabled', 'true',
                '--output', 'json'
            ])
            vcn = created.get('data', {})
            vcn_id = vcn.get('id', '')
            if not vcn_id:
                raise Exception("创建VCN失败：未获取到VCN ID")
            net_config['vcn_name'] = vcn_display
            net_config['vcn_id'] = vcn_id
            self._log(f"✅ 已创建 VCN: {vcn_display}", logger)
            return vcn_id, True
        except Exception as e:
            self._log(f"❌ 创建VCN失败: {e}", logger)
            raise

    def _create_network_resources(self, vcn_id: str, net_config: Dict[str, str], base: str, logger=None):
        """创建网络资源"""
        self._log("正在创建所有网络资源...", logger)
        
        # 创建网关
        self._create_internet_gateway(vcn_id, net_config, base, logger)
        # 设置路由表
        self._setup_route_table(vcn_id, net_config, logger)
        # 创建子网
        self._create_subnet(vcn_id, net_config, base, logger)
        # 创建NSG
        self._create_nsg(vcn_id, net_config, base, logger)

    def _create_internet_gateway(self, vcn_id: str, net_config: Dict[str, str], base: str, logger=None):
        """创建网关"""
        self._log("创建网关中...", logger)
        igw_display = f"{base}-internet-gateway"
        
        cmd = [
            'oci', 'network', 'internet-gateway', 'create',
            '--compartment-id', self.compartment_id,
            '--vcn-id', vcn_id,
            '--display-name', igw_display,
            '--is-enabled', 'true',
            '--output', 'json'
        ]
        
        data = self._run_cli_with_validation(cmd, "IGW", logger)
        igw_id = self._validate_response_data(data, "IGW", logger)
        net_config['internet_gateway_id'] = igw_id
        self._log(f"✅ 已创建网关: {igw_display}", logger)

    def _setup_route_table(self, vcn_id: str, net_config: Dict[str, str], logger=None):
        """设置路由表"""
        self._log("获取VCN默认路由表并更新规则...", logger)
        
        # 获取VCN默认路由表
        route_tables = self._run_cli([
            'oci', 'network', 'route-table', 'list',
            '--compartment-id', self.compartment_id,
            '--vcn-id', vcn_id,
            '--all', '--output', 'json'
        ])
        
        # 获取VCN默认路由表（VCN创建时自动生成）
        route_tables_data = route_tables.get('data', [])
        self._log(f"找到 {len(route_tables_data)} 个路由表", logger)
        
        if not route_tables_data:
            raise Exception("VCN中未找到任何路由表，这不应该发生")
        
        # VCN创建时自动生成的路由表就是默认路由表
        default_rt = route_tables_data[0]
        rt_name = default_rt.get('display-name', 'Unknown')
        self._log(f"使用VCN默认路由表: {rt_name}", logger)
        
        # 使用默认路由表并更新规则
        net_config['route_table_id'] = default_rt['id']
        
        # 更新路由规则（添加网关路由）
        rules = json.dumps([
            {"cidrBlock": "0.0.0.0/0", "networkEntityId": net_config['internet_gateway_id']},
            {"destination": "::/0", "destinationType": "CIDR_BLOCK", "networkEntityId": net_config['internet_gateway_id']}
        ])
        
        self._run_cli([
            'oci', 'network', 'route-table', 'update',
            '--rt-id', default_rt['id'],
            '--route-rules', rules,
            '--force',
            '--output', 'json'
        ])
        
        self._log(f"✅ 已更新默认路由表规则", logger)

    def _create_subnet(self, vcn_id: str, net_config: Dict[str, str], base: str, logger=None):
        """创建子网"""
        self._log("创建子网 (启用IPv6)...", logger)
        subnet_display = f"{base}-subnet"
        
        try:
            # 获取VCN IPv6前缀
            self._log("正在获取VCN的IPv6配置信息...", logger)
            vcn_info = self._run_cli([
                'oci', 'network', 'vcn', 'get',
                '--vcn-id', vcn_id,
                '--output', 'json'
            ])

            vcn_data = vcn_info.get('data', {})
            vcn_ipv6_cidrs = vcn_data.get('ipv6-cidr-blocks', [])
            vcn_ipv6_cidr = vcn_ipv6_cidrs[0] if vcn_ipv6_cidrs else ''
            
            self._log(f"VCN IPv6 CIDR信息: {vcn_ipv6_cidrs}", logger)
            
            if not vcn_ipv6_cidr:
                raise Exception("VCN未获取到IPv6 CIDR")
            
            # IPv6子网CIDR（VCN前缀 + 子网标识符）
            vcn_ipv6_prefix = vcn_ipv6_cidr.split('/')[0]
            subnet_ipv6_cidr = f"{vcn_ipv6_prefix.rstrip(':')}::/64"
            
            # 子网
            cmd = [
                'oci', 'network', 'subnet', 'create',
                '--compartment-id', self.compartment_id,
                '--vcn-id', vcn_id,
                '--cidr-block', '10.0.0.0/24',
                '--ipv6-cidr-block', subnet_ipv6_cidr,
                '--display-name', subnet_display,
                '--prohibit-public-ip-on-vnic', 'false',
                '--output', 'json'
            ]
            
            data = self._run_cli_with_validation(cmd, "子网", logger)
            subnet_id = self._validate_response_data(data, "子网", logger)
            net_config['subnet_id'] = subnet_id
            self._log(f"✅ 已创建子网: {subnet_display}", logger)
            
        except Exception as e:
            self._log(f"❌ 子网创建失败: {e}", logger)
            self._log(f"   VCN ID: {vcn_id}", logger)
            self._log(f"   子网名称: {subnet_display}", logger)
            raise

    def _create_nsg(self, vcn_id: str, net_config: Dict[str, str], base: str, logger=None):
        """创建网络安全组"""
        self._log("创建 NSG 并添加 22/TCP 入站规则...", logger)
        nsg_display = str(int(time.time() * 1000))
        
        cmd = [
            'oci', 'network', 'nsg', 'create',
            '--compartment-id', self.compartment_id,
            '--vcn-id', vcn_id,
            '--display-name', nsg_display,
            '--output', 'json'
        ]
        
        data = self._run_cli_with_validation(cmd, "NSG", logger)
        nsg_id = self._validate_response_data(data, "NSG", logger)
        net_config['nsg_id'] = nsg_id
        self._add_nsg_rules(nsg_id, logger)
        self._log(f"✅ 已创建 NSG: {nsg_display} 并添加规则", logger)

    def _save_network_config(self, net_config: Dict[str, str]):
        """保存网络配置"""
        valid_config = {k: v for k, v in net_config.items() if v}
        self.config['DEFAULT'].update(valid_config)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            self.config.write(f)

class OCIInstanceManager(BaseManager):
    """OCI实例管理器"""
    
    def __init__(self, config: configparser.ConfigParser, compartment_id: str):
        super().__init__(config, compartment_id)
        self.compute_client = oci.core.ComputeClient(oci.config.from_file())
    
    def get_image_id(self, arch: str) -> str:
        """根据架构获取镜像 ID 并写入配置文件"""
        key_image = f"{arch}_image"
        key_name = f"{arch}_name"
        image_id = self.config["DEFAULT"].get(key_image, "").strip()
        image_name = self.config["DEFAULT"].get(key_name, "").strip()
        
        if image_id and image_name:
            return image_id

        try:
            # 获取镜像列表
            cmd = [
                "oci", "compute", "image", "list",
                "--compartment-id", self.compartment_id,
                "--output", "json",
                "--all"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            images = json.loads(result.stdout)["data"]

            # 过滤 Ubuntu 22.04 Minimal 镜像
            images = [img for img in images if "Canonical-Ubuntu-22.04-Minimal" in img.get("display-name", "")]
            
            # 根据架构过滤
            if arch == "arm":
                images = [img for img in images if "aarch64" in img.get("operating-system-version", "")]
            elif arch == "amd":
                images = [img for img in images if "aarch64" not in img.get("operating-system-version", "")]
            else:
                raise ValueError(f"未知架构: {arch}")

            if not images:
                raise ValueError(f"未找到合适的 {arch.upper()} 镜像")

            # 选择最新创建镜像
            selected = max(images, key=lambda x: x["time-created"])
            image_id = selected["id"]
            image_name = selected.get("operating-system-version", "Unknown")

            print(f"获取 {arch.upper()} 镜像 ID: {image_id}, 系统版本: Ubuntu {image_name}")

            # 保存到配置文件
            self._save_config_values({key_image: image_id, key_name: image_name})
            return image_id

        except Exception as e:
            print(f"获取 {arch.upper()} 镜像失败: {e}")
            sys.exit(1)
    
    def _save_config_values(self, values: Dict[str, str]):
        """保存配置值到配置文件"""
        self.config["DEFAULT"].update(values)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            self.config.write(f)
    
    def get_config_or_cli(self, key: str, cli_cmd: list, json_path, description: str) -> str:
        """从配置文件或CLI获取配置值"""
        value = self.config["DEFAULT"].get(key, "").strip()
        if value:
            return value
            
        try:
            result = subprocess.run(cli_cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            if "data" in data and len(data["data"]) > 0:
                value = json_path(data)
                print(f"获取到 {description}: {value}")
                self._save_config_values({key: value})
                return value
            else:
                raise ValueError(f"无法获取 {description}")
        except Exception as e:
            print(f"获取 {description} 失败: {e}, 停止脚本")
            sys.exit(1)
    
    def create_instance(self, instance_config: InstanceConfig, image_id: str, 
                       availability_domain: str, subnet_id: str, ssh_key: str, 
                       disk_size: int, disk_vpus: int, nsg_id: str = "", logger=None) -> Tuple[oci.core.models.Instance, str]:
        """创建实例"""
        display_name = f"{int(time.time() * 1000)}-instance"
        
        nsg_ids = [nsg_id] if nsg_id else None
        
        instance_details = oci.core.models.LaunchInstanceDetails(
            availability_domain=availability_domain,
            compartment_id=self.compartment_id,
            display_name=display_name,
            image_id=image_id,
            shape=instance_config.shape,
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=instance_config.ocpus,
                memory_in_gbs=instance_config.memory_gb
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                assign_public_ip=True,
                assign_private_dns_record=True,
                subnet_id=subnet_id,
                nsg_ids=nsg_ids,
            ),
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                source_type="image",
                image_id=image_id,
                boot_volume_size_in_gbs=disk_size,
                boot_volume_vpus_per_gb=disk_vpus
            ),
            metadata={"ssh_authorized_keys": ssh_key}
        )
        
        try:
            response = self.compute_client.launch_instance(instance_details)
            if response and response.data:
                instance = response.data
                
                # 等待实例状态变为RUNNING
                self._log("等待实例启动...", logger)
                self._wait_for_instance_running(instance.id, logger)
                
                # 分配IPv6地址
                self._assign_ipv6_to_instance(instance.id, logger)
                
                return instance, display_name
            else:
                raise Exception("创建实例响应为空")
        except Exception as e:
            raise e
    
    def _wait_for_instance_running(self, instance_id: str, logger=None):
        """等待实例状态变为RUNNING"""
        max_wait_time = 300  # 最多等待5分钟
        check_interval = 10  # 每10秒检查一次
        
        start_time = time.time()
        while time.time() - start_time < max_wait_time:
            try:
                response = self.compute_client.get_instance(instance_id)
                lifecycle_state = response.data.lifecycle_state
                
                if lifecycle_state == "RUNNING":
                    self._log("✅ 实例已启动完成", logger)
                    return
                elif lifecycle_state in ["TERMINATED", "TERMINATING"]:
                    raise Exception(f"实例启动失败，状态: {lifecycle_state}")
                else:
                    self._log(f"实例状态: {lifecycle_state}，继续等待...", logger)
                    time.sleep(check_interval)
            except Exception as e:
                self._log(f"检查实例状态时出错: {e}", logger)
                time.sleep(check_interval)
        
        raise Exception("实例启动超时")
    
    def _assign_ipv6_to_instance(self, instance_id: str, logger=None):
        """给实例分配IPv6地址"""
        try:
            self._log("正在分配IPv6地址...", logger)
            
            # 获取实例的VNIC信息
            vnic_attachments = self.compute_client.list_vnic_attachments(
                compartment_id=self.compartment_id,
                instance_id=instance_id
            )
            
            if not vnic_attachments.data:
                raise Exception("未找到实例的VNIC附件")
            
            # 获取第一个VNIC
            vnic_attachment = vnic_attachments.data[0]
            vnic_id = vnic_attachment.vnic_id
            
            # 使用CLI命令分配IPv6地址
            cmd = [
                'oci', 'network', 'ipv6', 'create',
                '--vnic-id', vnic_id,
                '--output', 'json'
            ]
            
            result = self._run_cli(cmd)
            if result.get('data'):
                ipv6_address = result['data'].get('ip-address', 'Unknown')
                self._log(f"✅ 已分配IPv6地址: {ipv6_address}", logger)
            else:
                self._log("⚠️ IPv6地址分配可能失败，但继续执行", logger)
                
        except Exception as e:
            self._log(f"❌ 分配IPv6地址失败: {e}", logger)

def get_instance_config(arch: str, ocpus: Optional[int], memory: Optional[int], config: configparser.ConfigParser) -> InstanceConfig:
    """获取实例配置"""
    if arch == "arm":
        return InstanceConfig(
            machine_type="ARM",
            shape="VM.Standard.A1.Flex",
            ocpus=min(max(1, ocpus if ocpus is not None else 1), 4),
            memory_gb=min(max(1, memory if memory is not None else 6), 24),
            image_name=f"Ubuntu {config['DEFAULT'].get('arm_name', 'Unknown')}"
        )
    elif arch == "amd":
        return InstanceConfig(
            machine_type="AMD",
            shape="VM.Standard.E2.1.Micro",
            ocpus=1,
            memory_gb=1,
            image_name=f"Ubuntu {config['DEFAULT'].get('amd_name', 'Unknown')}"
        )
    else:
        print("❌ 未知架构类型")
        sys.exit(1)

def read_ssh_key(key_file_path: str) -> str:
    """读取SSH密钥"""
    try:
        with open(key_file_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        print(f"读取 ssh_key 失败: {e}, 停止脚本")
        sys.exit(1)

def build_info_message(instance_config: InstanceConfig, disk_size: int, disk_vpus: int, nsg_name: str = "") -> str:
    """信息消息"""
    base_msg = (
        f"机器类型: {instance_config.machine_type}, "
        f"OCPU: {instance_config.ocpus}C, "
        f"内存: {instance_config.memory_gb}G, "
        f"镜像: {instance_config.image_name}, "
        f"系统盘: {disk_size}G, "
        f"磁盘性能: {disk_vpus} VPUs/GB"
    )
    
    if nsg_name:
        base_msg += f", 网络安全组: {nsg_name}"
    
    return base_msg

def get_valid_input(prompt: str, min_val: int, max_val: int, default: int) -> int:
    """获取有效用户输入"""
    while True:
        user_input = input(prompt).strip()
        if not user_input:
            return default
        try:
            value = int(user_input)
            if min_val <= value <= max_val:
                return value
            else:
                print(f"❌ 值必须在{min_val}-{max_val}之间")
        except ValueError:
            print("❌ 请输入有效数字")

def get_time_interval() -> Union[int, str]:
    """获取时间间隔配置"""
    while True:
        time_input = input("请输入抢机时间（默认60秒，最小值10，支持单个数字或区间如30-60）: ").strip()
        if not time_input:
            return 60
        try:
            if "-" in time_input:
                parts = time_input.split("-")
                if len(parts) == 2:
                    min_time, max_time = int(parts[0]), int(parts[1])
                    if min_time >= 10 and min_time <= max_time:
                        return f"{min_time}-{max_time}"
                    else:
                        print("❌ 时间区间最小值必须≥10，且最小值不大于最大值")
                else:
                    print("❌ 区间格式错误，请使用如30-60的格式")
            else:
                interval = int(time_input)
                if interval >= 10:
                    return interval
                else:
                    print("❌ 抢机时间必须≥10秒")
        except ValueError:
            print("❌ 请输入有效数字或区间格式（如30-60）")

def user_input() -> UserConfig:
    """获取用户输入的配置"""
    print("请选择架构实例:")
    print("1 ARM 架构 VM.Standard.A1.Flex")
    print("2 AMD 架构 VM.Standard.E2.1.Micro")
    
    while True:
        choice = input("请输入选择 (1 或 2): ").strip()
        if choice in ['1', '2']:
            break
        print("❌ 无效选择，请输入 1 或 2")
    
    arch = "arm" if choice == "1" else "amd"
    config = ARCH_CONFIGS[arch]
    
    if arch == "arm":
        print("\n=== ARM架构配置 ===")
        ocpus = get_valid_input(
            f"请输入OCPU数量（{config['ocpu_range'][0]}-{config['ocpu_range'][1]}）C: ",
            config['ocpu_range'][0], config['ocpu_range'][1], config['default_ocpu']
        )
        memory = get_valid_input(
            f"请输入内存大小（{config['memory_range'][0]}-{config['memory_range'][1]}）G: ",
            config['memory_range'][0], config['memory_range'][1], config['default_memory']
        )
    else:
        print("\n=== AMD架构配置 ===")
        ocpus = config['default_ocpu']
        memory = config['default_memory']
    
    # 通用配置
    disk_size = get_valid_input("请输入硬盘大小（50-200）G: ", 50, 200, 50)
    vpus = 120  # 硬盘性能固定为120 VPUs/GB
    interval = get_time_interval()
    
    return UserConfig(
        arch=arch,
        ocpus=ocpus,
        memory=memory,
        disk_size=disk_size,
        vpus=vpus,
        interval=interval
    )

def select_nsg(conf: configparser.ConfigParser, compartment_id: str, vcn_id: str, logger=None) -> str:
    """选择网络安全组"""
    print("\n=== 网络安全组配置 ===")
    print("正在获取现有网络安全组列表...")
    
    # 获取现有NSG列表
    network_manager = NetworkManager(conf, compartment_id)
    existing_nsgs = network_manager.get_existing_nsgs(vcn_id)
    
    selected_nsg_id = ""
    if existing_nsgs:
        print("检测到现有网络安全组:")
        for i, nsg in enumerate(existing_nsgs, 1):
            print(f"{i} {nsg.get('display-name', 'Unknown')}")
        
        while True:
            choice = input(f"请选择网络安全组 (1-{len(existing_nsgs)}) 或输入 'new' 创建新的: ").strip()
            if choice.lower() == 'new':
                selected_nsg_id = network_manager.create_default_nsg(vcn_id, logger)
                print(f"✅ 已创建新的网络安全组")
                break
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= len(existing_nsgs):
                    selected_nsg_id = existing_nsgs[choice_num - 1]['id']
                    print(f"✅ 已选择网络安全组: {existing_nsgs[choice_num - 1].get('display-name', 'Unknown')}")
                    break
                else:
                    print(f"❌ 请输入 1-{len(existing_nsgs)} 之间的数字")
            except ValueError:
                print("❌ 请输入有效数字或 'new'")
    else:
        print("未检测到现有网络安全组，正在创建默认网络安全组...")
        selected_nsg_id = network_manager.create_default_nsg(vcn_id, logger)
        print("✅ 已创建默认网络安全组")
    
    # 是否重新配置安全列表规则
    print("\n=== 安全列表配置 ===")
    print("注意：安全列表规则配置只需要执行一次，后续运行时会自动跳过")
    
    while True:
        choice = input("是否要重新配置安全列表规则？(y/N): ").strip().lower()
        if choice in ['', 'n', 'no']:
            print("✅ 跳过安全列表规则配置")
            break
        elif choice in ['y', 'yes']:
            #print("正在配置安全列表规则...")
            network_manager.configure_security_list_rules(vcn_id, logger)
            break
        else:
            print("❌ 请输入 y 或 n")
    
    # 保存选择的NSG ID到配置
    conf["DEFAULT"]["nsg_id"] = selected_nsg_id
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        conf.write(f)
    
    return selected_nsg_id

def get_nsg_name(nsg_id: str) -> str:
    """获取NSG名称"""
    if not nsg_id:
        return ""
    
    try:
        nsg_data = subprocess.run([
            'oci', 'network', 'nsg', 'get',
            '--nsg-id', nsg_id,
            '--output', 'json'
        ], capture_output=True, text=True, check=True)
        nsg_info = json.loads(nsg_data.stdout)["data"]
        return nsg_info.get('display-name', 'Unknown')
    except Exception:
        return "Unknown"

def daemonize():
    """切换到后台运行"""
    try:
        # 分离终端
        pid = os.fork()
        if pid > 0:
            # 父进程退出
            print("脚本已在后台启动，进程ID:", pid)
            print("您可以关闭此终端，脚本将继续在后台运行")
            sys.exit(0)
        else:
            # 创建新的会话,子进程继续运行
            os.setsid()
            # 关闭标准输入输出
            sys.stdout.flush()
            sys.stderr.flush()
            with open('/dev/null', 'r') as dev_null:
                os.dup2(dev_null.fileno(), sys.stdin.fileno())
            with open('/dev/null', 'a+') as dev_null:
                os.dup2(dev_null.fileno(), sys.stdout.fileno())
                os.dup2(dev_null.fileno(), sys.stderr.fileno())
    except Exception as e:
        # fork失败，继续在前台运行
        print(f"切换到后台失败: {e}，继续在前台运行")

def _parse_interval_config(interval: Union[int, str]) -> Tuple[int, int, str]:
    """解析时间间隔配置"""
    if isinstance(interval, str) and "-" in interval:
        min_interval, max_interval = map(int, interval.split("-"))
        interval_display = f"{min_interval}-{max_interval}"
    else:
        min_interval = max_interval = interval
        interval_display = str(interval)
    return min_interval, max_interval, interval_display

def handle_service_error(e: oci.exceptions.ServiceError, current_interval: int, logger: Logger, 
                         info_msg: str, notifier: DingTalkNotifier) -> bool:
    """处理OCI服务错误"""
    status_code = e.status
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    # 定义错误处理映射
    error_handlers = {
        500: {
            'retry': True,
            'msg': f"{timestamp}: ❌ 服务器内部错误，等待 {current_interval} 秒重试",
            'special_case': ("Out of host capacity", f"{timestamp}: ❌ 主机容量不足，等待 {current_interval} 秒重试")
        },
        429: {
            'retry': True,
            'msg': f"{timestamp}: ❌ 请求频率过高，等待 {current_interval} 秒重试"
        },
        400: {
            'retry': False,
            'msg': f"{timestamp}: ⚠️ 已超出账户限制（请检查配额），停止脚本",
            'title': "⚠️ 抢机最终失败",
            'content': f"""⚠️ 抢机最终失败

{info_msg}

错误类型: 超出账户限制 (400)

错误时间: {timestamp}

状态: 脚本已停止，请检查账户配额"""
        }
    }
    
    handler = error_handlers.get(status_code, {
        'retry': False,
        'msg': f"{timestamp}: ⚠️ 未知错误，停止脚本\n异常内容: {e}",
        'title': "⚠️ 抢机最终失败",
        'content': f"""⚠️ 抢机最终失败

{info_msg}

错误类型: 未知错误 (状态码: {status_code})

错误时间: {timestamp}

错误状态: 脚本已停止

异常详情: {e}"""
    })
    
    # 处理特殊情况的500错误
    if status_code == 500 and "Out of host capacity" in str(e):
        logger.log(handler['special_case'][1])
    else:
        logger.log(handler['msg'])
    
    # 发送失败通知（如果需要）
    if not handler['retry'] and 'title' in handler:
        notifier.send_notification(handler['title'], handler['content'], "markdown", logger)
    
    return handler['retry']

def main():
    """主函数"""
    
    def _is_transient_error(e: Exception) -> bool:
        """判断是否为瞬时错误"""
        error_text = str(e)
        return any(marker in error_text for marker in TRANSIENT_ERROR_MARKERS)
    
    def _handle_transient_error(e: Exception, current_interval: int, logger: Logger):
        """处理瞬时错误"""
        msg = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}: ❌ 网络/连接异常，等待 {current_interval} 秒重试\n异常内容: {e}"
        logger.log(msg)
        try:
            time.sleep(current_interval)
        except KeyboardInterrupt:
            logger.log("\n用户中断，退出脚本")
            raise
    
    def _handle_fatal_error(e: Exception, info_msg: str, notifier: DingTalkNotifier, logger: Logger):
        """处理致命错误"""
        msg = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}: ⚠️ 未知异常，停止脚本\n异常内容: {e}"
        logger.log(msg)
        
        final_failure_content = f"""⚠️ 抢机最终失败

{info_msg}

错误类型: 未知异常

错误时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

错误状态: 脚本已停止

异常详情: {e}"""
        notifier.send_notification("⚠️ 抢机最终失败", final_failure_content, "markdown", logger)
    
    # 交互式获取用户输入
    user_config = user_input()
    
    # 读取配置
    conf = configparser.ConfigParser(strict=False, delimiters=('='))
    conf.optionxform = str
    conf.read(CONFIG_FILE)
    compartment_id = conf["DEFAULT"].get("tenancy")
    
    # 初始化组件
    logger = Logger(user_config.arch)
    notifier = DingTalkNotifier(conf)
    instance_manager = OCIInstanceManager(conf, compartment_id)
    
    # 获取镜像ID（同时保存镜像名称到配置文件）
    image_id = instance_manager.get_image_id(user_config.arch)

    # 网络资源检查/创建
    network_manager = NetworkManager(conf, compartment_id)
    net_ids = network_manager.ensure_network(logger)
    
    # 获取VCN ID用于NSG选择
    vcn_id = net_ids.get('vcn_id', '')
    if not vcn_id:
        vcn_id = conf["DEFAULT"].get("vcn_id", "").strip()
    
    # 清除保存的NSG ID，每次重新选择
    if "nsg_id" in conf["DEFAULT"]:
        del conf["DEFAULT"]["nsg_id"]
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            conf.write(f)
    
    # NSG选择（在网络资源创建之后）
    nsg_id = select_nsg(conf, compartment_id, vcn_id, logger)
    
    # 获取配置信息
    availability_domain = instance_manager.get_config_or_cli(
        "availability_domain",
        ["oci", "iam", "availability-domain", "list", "--compartment-id", compartment_id],
        lambda data: data["data"][0]["name"],
        "可用性域"
    )
    
    subnet_id = net_ids.get('subnet_id') or instance_manager.get_config_or_cli(
        "subnet_id",
        ["oci", "network", "subnet", "list", "--compartment-id", compartment_id],
        lambda data: data["data"][0]["id"],
        "子网"
    )
    
    # 读取SSH密钥
    ssh_key = read_ssh_key(conf["DEFAULT"].get("key_file"))
    
    # 获取实例配置
    instance_config = get_instance_config(user_config.arch, user_config.ocpus, user_config.memory, conf)
    
    # 获取NSG名称
    nsg_name = get_nsg_name(nsg_id)
    
    # 信息消息
    info_msg = build_info_message(instance_config, user_config.disk_size, user_config.vpus, nsg_name)
    logger.log(f"\n{info_msg}")
    
    # 确认继续
    input("\n祝君好运，按回车键开始抢机")
    
    # 处理时间间隔
    min_interval, max_interval, interval_display = _parse_interval_config(user_config.interval)
    
    print("=" * 50)
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 开始轮询，{interval_display} 秒请求一次")
    print("=" * 50)
    print("脚本已切换到后台运行模式，日志保存到 log 目录")
    print("查看实时日志，请使用: tail -f log/arm_YYYY-MM-DD.log 或 log/amd_YYYY-MM-DD.log")
    print("获取进程ID: ps aux | grep seckill.py")
    print("如需停止脚本，请使用: kill id 或 pkill -f seckill.py")
    print("=" * 50)
    
    # 切换到后台运行
    daemonize()
    
    try:
        while True:
            try:
                # 计算当前轮次的时间间隔
                current_interval = random.randint(min_interval, max_interval) if isinstance(user_config.interval, str) else user_config.interval
                
                # 创建实例
                instance, display_name = instance_manager.create_instance(
                    instance_config, image_id, availability_domain, subnet_id, ssh_key, 
                    user_config.disk_size, user_config.vpus, nsg_id, logger
                )
                
                # 验证实例创建是否成功
                if instance and hasattr(instance, 'id'):
                    # 成功通知
                    success_msg = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}: ✅ 创建成功"
                    logger.log(success_msg)
                    success_content = f"""🎉 抢机成功！

{info_msg}

开机时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

主机名称: {display_name}

网络安全组: {nsg_name}

IPv6支持: 已启用"""
                    
                    notifier.send_notification("🎉 抢机成功", success_content, "markdown", logger)
                    break
                else:
                    raise Exception("实例创建响应无效")

            except oci.exceptions.ServiceError as e:
                if not handle_service_error(e, current_interval, logger, info_msg, notifier):
                    break
                try:
                    time.sleep(current_interval)
                except KeyboardInterrupt:
                    logger.log("\n用户中断，退出脚本")
                    break
                    
            except KeyboardInterrupt:
                logger.log("\n用户中断，退出脚本")
                break
                
            except Exception as e:
                if _is_transient_error(e):
                    _handle_transient_error(e, current_interval, logger)
                    continue
                
                # 其余未知异常：记录并发送最终失败通知
                _handle_fatal_error(e, info_msg, notifier, logger)
                break
                
    finally:
        logger.close()

if __name__ == "__main__":
    main()