from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types


class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.servers = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]  # List of HTTP servers
        self.server_macs = {
            "10.0.0.1": "00:00:00:00:00:01",
            "10.0.0.2": "00:00:00:00:00:02",
            "10.0.0.3": "00:00:00:00:00:03",
            "10.0.0.4": "00:00:00:00:00:04",
            "10.0.0.5": "00:00:00:00:00:05",
        }  # Predefined IP to MAC mapping
        self.current_server = (
            0  # Index to keep track of which server to use for load balancing
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        buffer_id=None,
        idle_timeout=0,
        hard_timeout=0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            buffer_id=buffer_id or ofproto.OFP_NO_BUFFER,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
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
        ip = pkt.get_protocol(ipv4.ipv4)

        # Extract packet details for logging
        src_mac = eth.src
        dst_mac = eth.dst
        src_ip = ip.src if ip else None
        dst_ip = ip.dst if ip else None
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        src_port = tcp_pkt.src_port if tcp_pkt else None
        dst_port = tcp_pkt.dst_port if tcp_pkt else None

        # Log packet information before processing
        self.logger.info(
            "\nPacket before Redirecting:\n"
            "===============================\n"
            f"In Port         : {in_port}\n"
            f"Source MAC      : {src_mac}\n"
            f"Destination MAC : {dst_mac}\n"
            f"Source IP       : {src_ip or 'N/A'}\n"
            f"Destination IP  : {dst_ip or 'N/A'}\n"
            f"Source Port     : {src_port or 'N/A'}\n"
            f"Destination Port: {dst_port or 'N/A'}\n"
            "===============================\n\n\n"
        )

        if ip:
            if ip.proto == 6:  # TCP
                if (
                    ip.dst == "10.0.0.5" and tcp_pkt.dst_port == 80
                ):  # HTTP request destined to 10.0.0.5
                    selected_server = self.servers[self.current_server]
                    self.current_server = (self.current_server + 1) % len(self.servers)

                    selected_mac = self.server_macs.get(selected_server)
                    if not selected_mac:
                        self.logger.error(
                            "MAC address not found for %s", selected_server
                        )
                        return

                    self.logger.info(
                        f"Redirecting request to server {selected_server} with MAC {selected_mac}"
                    )

                    actions = [
                        parser.OFPActionSetField(eth_dst=selected_mac),
                        parser.OFPActionSetField(ipv4_dst=selected_server),
                        parser.OFPActionOutput(ofproto.OFPP_NORMAL),
                    ]

                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6,
                        ipv4_src=ip.src,
                        ipv4_dst="10.0.0.5",
                        tcp_src=tcp_pkt.src_port,
                        tcp_dst=tcp_pkt.dst_port,
                    )

                    self.add_flow(datapath, 10, match, actions, idle_timeout=30)

                    data = pkt.data
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=actions,
                        data=data,
                    )
                    datapath.send_msg(out)

                    # Log packet information after processing
                    self.logger.info(
                        "\nPacket after Redirecting:\n"
                        "===============================\n"
                        f"In Port         : {in_port}\n"
                        f"Source MAC      : {selected_mac}\n"
                        f"Destination MAC : {dst_mac}\n"
                        f"Source IP       : {src_ip or 'N/A'}\n"
                        f"Destination IP  : {selected_server}\n"
                        f"Source Port     : {src_port or 'N/A'}\n"
                        f"Destination Port: {dst_port or 'N/A'}\n"
                        "===============================\n\n\n"
                    )
                    return

                elif (
                    ip.src in self.servers and tcp_pkt.src_port == 80
                ):  # HTTP response from servers
                    self.logger.info("Handling HTTP response from server: %s", ip.src)

                    actions = [
                        parser.OFPActionSetField(eth_src=self.server_macs["10.0.0.5"]),
                        parser.OFPActionSetField(ipv4_src="10.0.0.5"),
                        parser.OFPActionOutput(ofproto.OFPP_NORMAL),
                    ]

                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6,
                        ipv4_src=ip.src,
                        ipv4_dst="10.0.0.5",
                        tcp_src=tcp_pkt.src_port,
                        tcp_dst=tcp_pkt.dst_port,
                    )

                    self.add_flow(datapath, 10, match, actions, idle_timeout=30)

                    data = pkt.data
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=actions,
                        data=data,
                    )
                    datapath.send_msg(out)

                    # Log packet information after processing
                    self.logger.info(
                        "\nPacket after Redirecting:\n"
                        "===============================\n"
                        f"In Port         : {in_port}\n"
                        f"Source MAC      : {self.server_macs['10.0.0.5']}\n"
                        f"Destination MAC : {dst_mac}\n"
                        f"Source IP       : {'10.0.0.5'}\n"
                        f"Destination IP  : {dst_ip or 'N/A'}\n"
                        f"Source Port     : {src_port or 'N/A'}\n"
                        f"Destination Port: {dst_port or 'N/A'}\n"
                        "===============================\n\n\n"
                    )
                    return

        # Default action: Flood the packet
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
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
        try:
            msg = ev.msg
            reason = msg.reason
            port_no = msg.desc.port_no

            ofproto = msg.datapath.ofproto
            if reason == ofproto.OFPPR_ADD:
                self.logger.info("Port added: %s", port_no)
            elif reason == ofproto.OFPPR_DELETE:
                self.logger.info("Port deleted: %s", port_no)
            elif reason == ofproto.OFPPR_MODIFY:
                self.logger.info("Port modified: %s", port_no)
            else:
                self.logger.info("Illegal port state: %s, Reason: %s", port_no, reason)
        except Exception as e:
            self.logger.error("Error processing port status: %s", str(e))
