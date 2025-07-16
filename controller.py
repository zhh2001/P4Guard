import logging
import warnings
from typing import Final

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff

logging.basicConfig(level=logging.INFO, format='[%(asctime)s %(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

categories = DeprecationWarning, FutureWarning, SyntaxWarning
for category in categories:
    warnings.filterwarnings("ignore", category=category)

ALARM_SESSION: Final[int] = 321

STRATEGY_DIRECT: Final[int] = 1
STRATEGY_WARM_UP: Final[int] = 2

SWITCH_NAME: Final[str] = "sw"
SWITCH_IP: Final[str] = '10.120.21.77'


class MyController(object):
    def __init__(self, switch_name: str = SWITCH_NAME):
        logging.info("控制器初始化开始")
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
        thrift_port = self.topo.get_thrift_port(self.switch_name)
        self.controller_thrift = SimpleSwitchThriftAPI(thrift_port, SWITCH_IP)
        self.init()
        logging.info("控制器初始化完成")

    def reset(self):
        logging.info("重置 gRPC 服务器")
        # 重置 gRPC 服务器
        self.controller.reset_state()

        # 保险一点，通过 ThriftAPI 重置一下
        self.controller_thrift.reset_state()

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
        cpu_port_intf = self.topo.get_cpu_port_intf(self.switch_name, quiet=False)
        cpu_port_intf = cpu_port_intf.replace("eth0", "eth1")
        sniff(iface=cpu_port_intf,
              prn=lambda packet: self.recv_msg_cpu(packet))

    def run_digest_loop(self):
        self.controller.table_clear('rule_tbl')
        h2_ip = self.topo.get_host_ip('h2')
        h2_id = 1
        h2_strategy = STRATEGY_WARM_UP
        h2_threshold = 800
        h2_warm_up_period_ms = 5000000
        h2_warm_up_factor = 2
        self.controller.table_add('rule_tbl', 'flow_control', [h2_ip],
                                  [str(h2_id), str(h2_strategy), '1', str(h2_threshold), str(h2_warm_up_period_ms),
                                   str(h2_warm_up_factor), '1000000'])
        warm_up_ms_per_threshold = h2_warm_up_period_ms // (h2_threshold - (h2_threshold >> h2_warm_up_factor))
        self.controller_thrift.register_write('warm_up_ms_per_threshold', h2_id, int(warm_up_ms_per_threshold))

        def listen_count():
            digest_name = 'reported_data'
            if self.controller.digest_get_conf(digest_name) is None:
                self.controller.digest_enable(digest_name)
            while True:
                digest = self.controller.get_digest_list()
                counter_data = digest.data[0].struct.members
                counter_data = (int.from_bytes(counter.bitstring, 'big', signed=False)
                                for counter in counter_data)
                passed_count, blocked_count = counter_data
                logging.info(f"【Direct】接受数量：{passed_count}，拒接数量：{blocked_count}")

        def listen_threshold():
            digest_name = 'warm_up_data'
            if self.controller.digest_get_conf(digest_name) is None:
                self.controller.digest_enable(digest_name)
            while True:
                digest = self.controller.get_digest_list()
                warm_up_data = digest.data[0].struct.members
                warm_up_data = (int.from_bytes(counter.bitstring, 'big', signed=False)
                                for counter in warm_up_data)
                threshold, passed_count, blocked_count = warm_up_data
                logging.info(f"【WarmUp】接受数量：{passed_count}，拒接数量：{blocked_count}")

        if h2_strategy == STRATEGY_DIRECT:
            listen_count()
        elif h2_strategy == STRATEGY_WARM_UP:
            listen_threshold()


def main():
    sw = MyController("sw")
    sw.run_cpu_port_loop()


if __name__ == "__main__":
    main()
    exit(0)
