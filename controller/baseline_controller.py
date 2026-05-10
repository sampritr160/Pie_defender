from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types
import time


class BaselineSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BaselineSDN, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.last_print = time.time()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

        self.logger.info("SWITCH CONNECTED dpid=%s", datapath.id)

    def should_ignore(self, eth):
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return True
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return True
        return False

    def print_mac_table(self, dpid):
        """DEMO ONLY: print controller MAC table"""
        self.logger.warning("========== MAC TABLE (dpid=%s) ==========", dpid)
        for mac, port in self.mac_to_port[dpid].items():
            self.logger.warning("  %s  -> port %s", mac, port)
        self.logger.warning("========================================")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        if self.should_ignore(eth):
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src = eth.src
        dst = eth.dst

        # Learn source MAC
        if src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src] = in_port
            self.logger.info("LEARN %s -> port %s", src, in_port)

        # PRINT MAC TABLE EVERY 5 SECONDS (for demo)
        if time.time() - self.last_print > 5:
            self.print_mac_table(dpid)
            self.last_print = time.time()

        # ALWAYS FLOOD ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._flood(datapath, msg, in_port)
            return

        # Known destination → install flow
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=1,
                match=match,
                instructions=inst,
                idle_timeout=30
            )
            datapath.send_msg(mod)

            self.logger.info("FLOW %s -> %s via %s", src, dst, out_port)
            self._send(datapath, msg, out_port)
        else:
            self._flood(datapath, msg, in_port)

    def _send(self, datapath, msg, out_port):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

    def _flood(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
