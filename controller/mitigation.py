from ryu.ofproto import ofproto_v1_3


class MitigationEngine:
    """
    Module-3: Flow Rule Management (Mitigation)
    Responsible ONLY for installing drop rules
    """

    def __init__(self, logger):
        self.logger = logger

    def install_drop_rule(self, datapath, in_port,
                          idle_timeout=300, hard_timeout=600):
        """
        Install a high-priority DROP rule on a switch port
        """

        parser = datapath.ofproto_parser

        drop_flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=parser.OFPMatch(in_port=in_port),
            instructions=[],      # no actions = DROP
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(drop_flow)

        self.logger.error(
            "MITIGATION APPLIED | dpid=%s port=%s",
            datapath.id, in_port
        )
