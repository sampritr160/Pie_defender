from ryu.ofproto import ofproto_v1_3


class MitigationEngine2:
    """
    Module 3: Mitigation Engine
    Only installs drop rules when told by controller
    """

    def __init__(self, logger):
        self.logger = logger
        self.blocked_ports = set()
    
    def install_drop_rule(self, datapath, in_port, 
                         idle_timeout=300, hard_timeout=600):
        """
        Install drop rule for specific port
        Called by controller when attack detected
        """
        
        dpid = datapath.id
        port_key = (dpid, in_port)
        
        # Avoid duplicate blocking
        if port_key in self.blocked_ports:
            return
        
        self.blocked_ports.add(port_key)
        
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Match ALL packets from this port
        match = parser.OFPMatch(in_port=in_port)
        
        # No actions = DROP
        drop_flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,  # Higher than normal flows
            match=match,
            instructions=[],  # Empty instructions = DROP
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        
        datapath.send_msg(drop_flow)
        
        self.logger.warning(
            f"BLOCKED: Switch {dpid}, Port {in_port}"
        )
    
    def install_mac_drop_rule(self, datapath, src_mac,
                             idle_timeout=300, hard_timeout=600):
        """
        Install drop rule for specific MAC address
        More precise blocking
        """
        
        parser = datapath.ofproto_parser
        
        # Match packets from this MAC
        match = parser.OFPMatch(eth_src=src_mac)
        
        drop_flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        
        datapath.send_msg(drop_flow)
        
        self.logger.warning(
            f"BLOCKED MAC: {src_mac} on Switch {datapath.id}"
        )
    
    def unblock_port(self, datapath, in_port):
        """
        Remove block from port (manual unblock)
        """
        
        dpid = datapath.id
        port_key = (dpid, in_port)
        
        if port_key not in self.blocked_ports:
            return False
        
        parser = datapath.ofproto_parser
        
        # Delete the drop rule
        match = parser.OFPMatch(in_port=in_port)
        
        delete_flow = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto_v1_3.OFPFC_DELETE,
            priority=100,
            match=match,
            out_port=ofproto_v1_3.OFPP_ANY,
            out_group=ofproto_v1_3.OFPG_ANY
        )
        
        datapath.send_msg(delete_flow)
        
        self.blocked_ports.remove(port_key)
        
        self.logger.info(
            f"UNBLOCKED: Switch {dpid}, Port {in_port}"
        )
        
        return True
    
    def is_port_blocked(self, dpid, in_port):
        """Check if port is currently blocked"""
        return (dpid, in_port) in self.blocked_ports
    
    def get_blocked_ports(self):
        """Get list of all blocked ports"""
        return list(self.blocked_ports)