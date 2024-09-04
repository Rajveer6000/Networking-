import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        tcp_header = pkt.get_protocol(tcp.tcp)

        # Initialize variables to store IP addresses and ports
        src_ip = ""
        dst_ip = ""
        src_port = None
        dst_port = None

        if ipv4_header:
            src_ip = ipv4_header.src
            dst_ip = ipv4_header.dst

            # If it's a TCP packet, extract the ports
            if tcp_header:
                src_port = tcp_header.src_port
                dst_port = tcp_header.dst_port

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Log details of each packet
        self.logger.info(
            "\nPacket:\n"
            "===============================\n"
            f"In Port    : {in_port}\n"
            f"Source MAC      : {src}\n"
            f"Destination MAC : {dst}\n"
            f"Source IP       : {src_ip or 'N/A'}\n"
            f"Destination IP  : {dst_ip or 'N/A'}\n"
            f"Source Port     : {src_port or 'N/A'}\n"
            f"Destination Port: {dst_port or 'N/A'}\n"
            "===============================\n\n\n"
        )

        # Learn a MAC address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Initialize actions
        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        # Send the packet out
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("Port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("Port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("Port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)
