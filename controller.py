import warnings
from typing import Final

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff

categories = DeprecationWarning, FutureWarning, SyntaxWarning
for category in categories:
    warnings.filterwarnings("ignore", category=category)

ALARM_SESSION: Final[int] = 321


class MyController(object):
    def __init__(self, switch_name: str = "sw"):
        print("控制器初始化开始")
        self.topo = load_topo("topology.json")
        self.switch_name = switch_name
        self.cpu_port = self.topo.get_cpu_port_index(self.switch_name)
        device_id = self.topo.get_p4switch_id(switch_name)
        grpc_port = self.topo.get_grpc_port(switch_name)
        sw_data = self.topo.get_p4rtswitches()[switch_name]
        self.controller = SimpleSwitchP4RuntimeAPI(
            device_id=device_id,
            grpc_port=grpc_port,
            p4rt_path=sw_data["p4rt_path"],
            json_path=sw_data["json_path"],
        )
        self.init()
        print("控制器初始化完成")

    def reset(self):
        print("重置 gRPC 服务器")
        # 重置 gRPC 服务器
        self.controller.reset_state()

        # 保险一点，通过 ThriftAPI 重置一下
        thrift_port = self.topo.get_thrift_port(self.switch_name)
        controller_thrift = SimpleSwitchThriftAPI(thrift_port, "localhost")
        controller_thrift.reset_state()

    def init(self):
        self.reset()
        self.add_ipv4_table_entry()
        self.add_clone_session()

    def add_ipv4_table_entry(self):
        # net.enableCpuPort('sw') 导致交换机被重置
        # 这里重新添加一下各个表项
        self.controller.table_set_default("ipv4_lpm", "drop", [])
        self.controller.table_set_default("ipv4_dpi_lpm", "drop", [])

    def add_clone_session(self):
        if self.cpu_port:
            self.controller.cs_create(ALARM_SESSION, [self.cpu_port])

    def recv_msg_cpu(self, pkt):
        pkt = Ether(raw(pkt))
        print("收到交换机的克隆数据包", pkt)

    def run_cpu_port_loop(self):
        cpu_port_intf = self.topo.get_cpu_port_intf(self.switch_name, quiet=False).replace("eth0", "eth1")
        sniff(iface=cpu_port_intf,
              prn=lambda packet: self.recv_msg_cpu(packet))


def main():
    sw = MyController("sw")
    sw.run_cpu_port_loop()


if __name__ == "__main__":
    main()
    exit(0)
