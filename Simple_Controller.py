__author__ = 'Ehsan'

""" ryu.base.app_manager:
The central management of Ryu applications.
- Load Ryu applications
- Provide contexts to Ryu applications
- Route messages among Ryu applications
"""
from ryu.base import app_manager

"""ryu.controller.ofp_event:
OpenFlow event definitions.
"""
from ryu.controller import ofp_event

# Version negotiated and sent features-request message
from ryu.controller.handler import CONFIG_DISPATCHER

from ryu.ofproto import ofproto_v1_3

# Switch-features message received and sent set-config message
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

"""ryu.lib.packet:
Ryu packet library. Decoder/Encoder implementations of popular protocols like TCP/IP.
"""
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib import dpid as dpid_lib

"""
Usage Example:
    1. Run this application:
    $ sudo ryu-manager --verbose --observe-links < Address of Simple_controller.py>
    In my case I have:~/ryu/bin/ryu-manager --verbose ~/HelloSDN/Simple_Controller.py
    2. Add single switche in mininet (use your favorite method):
    $ sudo mn --topo single,3 --mac --controller remote --switch ovsk

For a better instructions on using this code first do http://sdnhub.org/tutorials/ryu/. 

"""

"""
In order to implement as a Ryu application, ryu.base.app_manager.RyuApp is inherited. Also, to use
OpenFlow 1.3, the OpenFlow 1.3 version is specified for OFP_VERSIONS.
The http://osrg.github.io/ryu-book/en/html/switching_hub.html explain similar features pretty good.
"""


class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("[Ehsan] Received EventOFPSwitchFeatures")
        msg = ev.msg
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    """
    This function is used to create a flow with give actions and matches for a specified datapath.

    Reminder: The datapath class is to describe an OpenFlow switch connected to this controller.

    datapath:
        A class to describe an OpenFlow switch connected to this controller.
        http://ryu-zhdoc.readthedocs.org/en/latest/ryu_app_api.html#ryu-controller-controller-datapath

    actions :
        is a list of openflow action structs defined in Ryu.
        For openflow version 1.3 the list of action structs is in the below link:
        http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_3_ref.html#action-structures

    match :
        Flow Match Structure which is described in below link:
        http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_3_ref.html#flow-match-structure

    """
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        """
        Instructions is essentially what to do with the actions.
        You could essentially OFPIT_WRITE_ACTIONS, OFPIT_APPLY_ACTIONS or OFPIT_CLEAR_ACTIONS teh actions.

        Source: http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_3_ref.html?highlight=ofpinstructionactions
        """
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        """
        A Modify Flow entry message has to be created in order to send packet_out.
        The controller sends Modify Flow entry message to modify the flow table.

        Note that it requires the datapath object, match objecct and the actions. The actions is embeded in inst. (in above line)
        """
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    """
    This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
    tells Ryu when the decorated function should be called.

    Arguments of the decorator:
        1. The first argument of the decorator indicates an event that makes function called. As you expect easily, every time
        Ryu gets a packet_in message, this function is called.
        2. The second argument indicates the state of the switch. Probably, you want to ignore packet_in messages before the
        negotiation between Ryu and the switch finishes. Using MAIN_DISPATCHER as the second argument means this function
        is called only after the negotiation completes.
    """

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info("[Ehsan] Received EventOFPPacketIn")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        """
        ryu.controller.ofp_event module exports event classes which describe receptions of OpenFlow messages from connected
        switches. By convention, they are named as ryu.controller.ofp_event.EventOFPxxxx where xxxx is the name of the
        corresponding OpenFlow message. For example, EventOFPPacketIn for packet-in message.
        OpenFlow event classes have at least the following attributes.
        Attribute 	         Description
           msg 	                An object which describes the corresponding OpenFlow message.
           msg.datapath 	    A ryu.controller.controller.Datapath instance which describes an OpenFlow switch from
                                which we received this OpenFlow message.

        Source: http://ryu-zhdoc.readthedocs.org/en/latest/ryu_app_api.html#ryu-controller-ofp-event-eventofpstatechange
        """
        msg = ev.msg
        datapath = msg.datapath

        """
        ryu.controller.controller.Datapath is a class to describe an OpenFlow switch connected to controller. Below is list of some attributes: (note for the full list visit the link)
        Attribute 	    Description
          id 	           64-bit OpenFlow Datapath ID. Only available for ryu.controller.handler.MAIN_DISPATCHER phase.
          ofproto 	       A module which exports OpenFlow definitions, mainly constants appeared in the specification, for the negotiated OpenFlow version. Example: ryu.ofproto.ofproto_v1_0 for OpenFlow 1.0.
          ofproto_parser   A module which exports OpenFlow wire message encoder and decoder for the negotiated OpenFlow version. For example, ryu.ofproto.ofproto_v1_0_parser for OpenFlow 1.0.

        Source: http://ryu-zhdoc.readthedocs.org/en/latest/ryu_app_api.html#ryu-controller-controller-datapath
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        """
        Based on an event we are listening we use match method to extract information for that event.
        In this case, we are listening for packet_in msg. From source below, we know that packet_in message has the following attributes:
        Attribute 	Description
           buffer_id 	ID assigned by datapath.
           total_len 	Full length of frame.
           in_port 	Port on which frame was received.
           reason 	Reason packet is being sent.
                          OFPR_NO_MATCH    -> There was no flow that had a match
                          OFPR_ACTION      -> The action was to send a packet_in for this match
                          OFPR_INVALID_TTL ->
           data 	Ethernet frame.

        So the cose msg.match['in_port'] would extract the information related to in_port attribute. Bellow calls are valid too:
        msg.match['reason'] -> The reason the packet in was generated.
        msg.match['data']
        Source: http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_0_ref.html#packet-in-message
        """
        in_port = msg.match['in_port']
        """
        Ryu packet library helps you to parse and build various protocol packets.
        An instance is used to either decode or encode a single packet.
        data is a bytearray to describe a raw datagram to decode. When decoding, a Packet object is iteratable.

        Have a look at the link below for further information.

        Source: http://ryu-zhdoc.readthedocs.org/en/latest/library_packet.html
        """
        # From above comment we see that the data attribute contains the Ethernet apcket.
        # the packet.packet() method converts that ethernet data to packet object.
        pkt = packet.Packet(msg.data)
        """
        Returns a list of protocols that matches to the specified protocol.
        Note: This is a list so we have [0] at the end
        """
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # Mac address of the destination
        dst = eth.dst
        # Mac address of the source
        src = eth.src

        # Below initialized the data structure
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("\tpacket in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        """
        Below means that in order to get to a machine/device with mac address of dst the switch has to forward the
        packet to its port with port number equal to in_port.
        Note that in_port is the port number on the switch.
        """
        self.mac_to_port[dpid][src] = in_port

        """
        If the destination address is learned then set the out_put part to the value stored mac_to_port[dpid][dst].
            The out_port would be used in the packet_out to tell the switch to forward the messge to its port with port number of out_port.
        If the destination is not learned then tell the switch to flood message
            This is done by sending a packet_out message to switch telling it to flood teh message.
        """
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        """
        In order to send a packet_out two main things are needed: 1. Match  2. Action
         If the packet header are same as the ones specified in Match then do an anction that is specified in Action list.
         Match is specifying teh circumstances that an action should be executed.
        """
        """
        Rye has Action structs based on the oprnflow version.
        based on the "parser" which we set above, the proper version of the action is used.
        For example for open flow 1.3 the ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput will be sued.

        Source: http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_3_ref.html?highlight=ofpactionoutput#action-structures
        """
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            """
            The code bellow specifies that when a message comes to the switch and in_port=in_port and eth_dst=dst then do some action.
            """
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                """
                Below constructs a message which is going to be sent to datapath object with the proper match and
                actions object.

                Note: the method add_flow is defined in this file and is not part of ryu.
                """
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        """
        Note: If the out_port attribute of the action is equal to ofproto.OFPP_FLOOD, it means flood the message.
        """
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        # After preparing the packet_out, the message is sent here
        datapath.send_msg(out)

    """
    EventOFPPortStatus: An event class for switch port status notification.
    The bellow handles the event.
    """

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        # self.logger.info("[Ehsan] Received EventOFPPortStatus")

        """ Port status message
        The switch notifies controller of change of ports.
        Attribute     |     Description
        --------------------------------
        reason        |     One of the following values.
                      |     OFPPR_ADD
                      |     OFPPR_DELETE
                      |     OFPPR_MODIFY
        --------------------------------
        desc          |     instance of OFPPort
        """
        msg = ev.msg
        dp = msg.datapath
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("\tport added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("\tport deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("\tport modified %s", port_no)
            dp_str = dpid_lib.dpid_to_str(dp.id)
            self.logger.info("\t[Ehsan] Sending send_port_desc_stats_request to datapath id : " + dp_str)
            self.send_port_desc_stats_request(dp)
        else:
            self.logger.info("\tIlleagal port state %s %s", port_no, reason)

    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        """
        class ryu.ofproto.ofproto_v1_3_parser.OFPPortStatsRequest(datapath, flags=0, port_no=4294967295, type_=None)
        Port statistics request message

        The controller uses this message to query information about ports statistics.

        Attribute  |  Description
        --------------------------
        flags	   |  Zero or OFPMPF_REQ_MORE
        port_no	   |  Port number to read (OFPP_ANY to all ports)
        """
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    """
    Creates an event handler that receives the PortStatsReply message.
    The bellow handles the event.
    """

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        # self.logger.info("[Ehsan] Received EventOFPPortStatsReply")
        # self.logger.info('PortStats: \n')

        """ Port statistics reply message
        The switch responds with this message to a port statistics request.

        Attribute | Description
        -----------------------
        body      | List of OFPPortStats instance
        """
        for stat in ev.msg.body:
            self.logger.info("\tport_no=%d "
                             "rx_packets=%d tx_packets=%d "
                             "\n \trx_bytes=%d tx_bytes=%d "
                             "rx_dropped=%d tx_dropped=%d "
                             "rx_errors=%d tx_errors=%d "
                             "\n \trx_frame_err=%d rx_over_err=%d rx_crc_err=%d "
                             "\n \tcollisions=%d duration_sec=%d duration_nsec=%d" %
                             (stat.port_no,
                              stat.rx_packets, stat.tx_packets,
                              stat.rx_bytes, stat.tx_bytes,
                              stat.rx_dropped, stat.tx_dropped,
                              stat.rx_errors, stat.tx_errors,
                              stat.rx_frame_err, stat.rx_over_err,
                              stat.rx_crc_err, stat.collisions,
                              stat.duration_sec, stat.duration_nsec))

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    """
    EventOFPPortDescStatsReply: an event where it is fired when Port description reply message
    The bellow handles the event.
    """

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        # self.logger.info('OFPPortDescStatsReply received: \n')
        """
        Port description reply message
        The switch responds with this message to a port description request.
        Attribute   |    Description
        ------------|---------------
        body        |    List of OFPPortDescStats instance
        """
        for p in ev.msg.body:
            self.logger.info("\t port_no=%d hw_addr=%s name=%s config=0x%08x "
                             "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
                             "\n \t supported=0x%08x peer=0x%08x curr_speed=%d "
                             "max_speed=%d" %
                             (p.port_no, p.hw_addr,
                              p.name, p.config,
                              p.state, p.curr, p.advertised,
                              p.supported, p.peer, p.curr_speed,
                              p.max_speed))
