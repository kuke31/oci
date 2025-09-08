"""
pip3 install prettytable

"""
import configparser, oci
from prettytable import PrettyTable

# 读取配置
conf = configparser.ConfigParser(strict=False, delimiters=('='))
conf.optionxform = str
conf.read("/root/.oci/config")
compartment_id = conf["DEFAULT"].get("tenancy")

# 从配置文件加载 OCI 配置信息
config = oci.config.from_file()

# 创建客户端
compute_client = oci.core.ComputeClient(config)
vcn_client = oci.core.VirtualNetworkClient(config)
block_client = oci.core.BlockstorageClient(config)

# 获取所有实例
instances = compute_client.list_instances(compartment_id).data

table = PrettyTable(["display-name", "Public_IP", "Private_IP", "IPv6", "Size_GB"])

for instance in instances:
    # 获取实例VNIC
    vnics = compute_client.list_vnic_attachments(compartment_id, instance_id=instance.id).data
    for vnic_attachment in vnics:
        vnic = vcn_client.get_vnic(vnic_attachment.vnic_id).data
        ipv6_addrs = vnic.ipv6_addresses
        ipv6 = ipv6_addrs[0] if ipv6_addrs else ""

        # 获取实例硬盘大小
        boot_volumes = compute_client.list_boot_volume_attachments(
            compartment_id=compartment_id,
            instance_id=instance.id,
            availability_domain=instance.availability_domain
        ).data

        size_gb = ""
        if boot_volumes:
            boot_vol_id = boot_volumes[0].boot_volume_id
            boot_vol = block_client.get_boot_volume(boot_vol_id).data
            size_gb = f"{boot_vol.size_in_gbs}G"

        table.add_row([
            instance.display_name,
            vnic.public_ip or "",
            vnic.private_ip,
            ipv6,
            size_gb
        ])

print(table)
