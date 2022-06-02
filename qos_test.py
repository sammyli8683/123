#!/usr/bin/python3

import socket
import sys
import os
from datetime import datetime
from scapy.all import *
from scapy.contrib.pfcp import *
import unittest

class IE_CPFunctionFeatures_r16(IE_CPFunctionFeatures):
    default_length = 3
    fields_desc = IE_Base.fields_desc + [
        BitField("UIAUR", 0, 1),
        BitField("APDR", 0, 1),
        BitField("MPAS", 0, 1),
        BitField("BUNDL", 0, 1),
        BitField("SSET", 0, 1),
        BitField("EPFARL", 0, 1),
        BitField("OVRL", 0, 1),
        BitField("LOAD", 0, 1),
        BitField("spare", 0, 16),
        ExtraDataField("extra_data"),
    ]

class IE_UE_IP_Address_r16(IE_UE_IP_Address):
    name = "IE UE IP Address"
    ie_type = 93
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 1),
        BitField('IP6PL', 0, 1),
        BitField('CHV5', 0, 1),
        BitField('CHV4', 0, 1),
        BitField('IPv6D', 0, 1),
        BitField("SD", 0, 1),  # source or dest
        BitField("V4", 0, 1),
        BitField("V6", 0, 1),
        ConditionalField(IPField("ipv4", 0), lambda x: x.V4 == 1),
        ConditionalField(IP6Field("ipv6", 0), lambda x: x.V6 == 1),
        ExtraDataField("extra_data"),
    ]

class IE_Source_IP_Address_r16(IE_Base):
    name = "IE Source IP Address"
    ie_type = 192
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("MPL", 0, 1),
        BitField("V4", 0, 1),
        BitField("V6", 0, 1),
        ConditionalField(IPField("ipv4", 0), lambda x: x.V4 == 1),
        ConditionalField(IP6Field("ipv6", 0), lambda x: x.V6 == 1),
        ExtraDataField("extra_data"),
    ]

def timestamp() :
    return int(datetime.now().timestamp() - datetime(1900,1,1).timestamp())

def pcap(pfcp_ie) :
    pkt = \
        Ether()/\
        IP(src = '127.0.0.1', dst = '127.0.0.1')/\
        UDP(sport = 8805, dport = 8805)/\
        pfcp_ie

    name = os.path.basename(__file__).replace('.py', '.pcap')
    wrpcap(name, pkt, append=True)
    pfcp_ie = PFCP(pfcp_ie)
    #pfcp_ie.show()

class SMF :
        def __init__(self, host, port) :
                self.n6_network_instance = 'N6'
                self.n3_network_instance = 'N3'
                self.seq_num = 1
                self._host = host
                self._port = port

                self._conf = {
                        'NodeId' : 'smf.affirmed.com.sim',
                        }

                self._qer_id = 0
                self._pdr_far_id = 0
                self._pdr_prcedence = 0
                self._qfi = 0

        def send_request(self, msg) :
                pcap(msg)
                self.seq_num += 1

                self._server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server.connect((self._host, self._port))
                self._server.sendall(msg)

                resp = self._server.recv(1024)
                self._server.close()

                return self._handle_pfcp_massages(resp)

        def _handle_pfcp_massages(self, raw_msg) :
                pcap(raw_msg)
                pfcp_ie = PFCP(raw_msg) 

                if pfcp_ie.haslayer('PFCPAssociationSetupResponse') :
                        ie = pfcp_ie[PFCPAssociationSetupResponse]
                        return ie[IE_Cause].cause

                elif pfcp_ie.haslayer('PFCPAssociationReleaseResponse') :
                        ie = pfcp_ie[PFCPAssociationReleaseResponse]
                        return ie[IE_Cause].cause

                elif pfcp_ie.haslayer('PFCPSessionEstablishmentResponse') :
                        ie = pfcp_ie[PFCPSessionEstablishmentResponse]
                        try : 
                            seid = ie[IE_FSEID].seid
                        except :
                            seid = -1

                        return ie[IE_Cause].cause, seid

                elif pfcp_ie.haslayer('PFCPSessionModificationResponse') :
                        ie = pfcp_ie[PFCPSessionModificationResponse]
                        return ie[IE_Cause].cause

                elif pfcp_ie.haslayer('PFCPSessionDeletionResponse') :
                        ie = pfcp_ie[PFCPSessionDeletionResponse]
                        return ie[IE_Cause].cause

                elif pfcp_ie.haslayer('PFCPHeartbeatResponse') :
                        ie = pfcp_ie[PFCPHeartbeatResponse]
                        return ie[IE_RecoveryTimeStamp].timestamp

        def _gen_traffic_endpoint(self) :
                ret = {'N6' : {'id' : 1}, 'N3' : {'id' : 2}}

                ret['N6']['ie'] = \
                        IE_CreateTrafficEndpoint(IE_list = [
                                IE_TrafficEndpointId(id = ret['N6']['id']),
                                IE_NetworkInstance(instance = 'N6'),
                                IE_UE_IP_Address_r16(CHV4 = 1), #CHV4
                        ])

                ret['N3']['ie'] = \
                        IE_CreateTrafficEndpoint(IE_list = [
                                IE_TrafficEndpointId(id = ret['N3']['id']),
                                IE_FTEID(CH = 1, V6 = 1, V4 = 1),
                                IE_NetworkInstance(instance = 'N3'),
                                IE_QFI(QFI = 1),
                        ])

                return ret

        def _gen_qer(self, mbr, gbr=None) :
                self._qer_id += 1
                if gbr is None : 
                        ie = \
                                IE_CreateQER(IE_list = [
                                        IE_QER_Id(id = self._qer_id),
                                        IE_GateStatus(ul = 'OPEN', dl = 'OPEN'),
                                        IE_MBR(ul = mbr['ul'], dl = mbr['dl']),
                                        IE_QFI(QFI = self._qer_id)
                                ])
                else :
                        ie = \
                                IE_CreateQER(IE_list = [
                                        IE_QER_Id(id = self._qer_id),
                                        IE_GateStatus(ul = 'OPEN', dl = 'OPEN'),
                                        IE_MBR(ul = mbr['ul'], dl = mbr['dl']),
                                        IE_GBR(ul = gbr['ul'], dl = gbr['dl']),
                                        IE_QFI(QFI = self._qer_id)
                                ])

                return self._qer_id, ie

        def _gen_flow(self, qer_id, tf_id, sdf=None) :
                ret = {'UL' : {}, 'DL' : {}}
                self._pdr_far_id += 1
                self._pdr_prcedence += 1

                if sdf is None :
                        pdi = IE_PDI(IE_list = [
                                IE_SourceInterface(interface = "Access"),
                                IE_TrafficEndpointId(id = tf_id['ul']),
                                IE_QFI(QFI = 1)
                                ])

                else :
                        pdi = IE_PDI(IE_list = [
                                IE_SourceInterface(interface = "Access"),
                                IE_TrafficEndpointId(id = tf_id['ul']),
                                sdf,
                                IE_QFI(QFI = 1)
                                ])

                ie_list = [
                        IE_PDR_Id(id = self._pdr_far_id),
                        IE_Precedence(precedence = self._pdr_prcedence),
                        pdi,
                        IE_OuterHeaderRemoval(header = "GTP-U/UDP/IP"),
                        IE_FAR_Id(id = self._pdr_far_id),
                        ]

                for i in qer_id :
                        ie_list.append(IE_QER_Id(id = i))

                ret['UL']['PDR'] = IE_CreatePDR(IE_list = ie_list)

                ret['UL']['FAR'] = \
                        IE_CreateFAR(IE_list = [
                                IE_FAR_Id(id = self._pdr_far_id),
                                IE_ApplyAction(FORW = 1),
                                IE_ForwardingParameters(IE_list = [
                                    IE_DestinationInterface(interface = "SGi-LAN/N6-LAN"),
                                    IE_NetworkInstance(instance = 'N6')
                                    ])
                        ])

                self._pdr_far_id += 1
                self._pdr_prcedence += 1

                if sdf is None :
                        pdi = IE_PDI(IE_list = [
                                IE_SourceInterface(interface = "SGi-LAN/N6-LAN"),
                                IE_TrafficEndpointId(id = tf_id['dl']),
                                ])

                else :
                        pdi = IE_PDI(IE_list = [
                                IE_SourceInterface(interface = "SGi-LAN/N6-LAN"),
                                IE_TrafficEndpointId(id = tf_id['dl']),
                                sdf,
                                ])

                ie_list = [
                        IE_PDR_Id(id = self._pdr_far_id),
                        IE_Precedence(precedence = self._pdr_prcedence),
                        pdi,
                        IE_FAR_Id(id = self._pdr_far_id)
                        ]

                for i in qer_id :
                        ie_list.append(IE_QER_Id(id = i))

                ret['DL']['PDR'] = IE_CreatePDR(IE_list = ie_list)

                ret['DL']['FAR'] = \
                        IE_CreateFAR(IE_list = [
                                IE_FAR_Id(id = self._pdr_far_id),
                                IE_ApplyAction(BUFF = 1),
                                IE_BAR_Id(id = 1) # TODO
                        ])

                return ret

        def _gen_sdf_flow_description(self, sdf_fd) :
                sdf = IE_SDF_Filter(FD = 1, flow_description = sdf_fd, 
                                BID = 1, sdf_filter_id = 0)
                return sdf

        def _gen_header_enrichment(self) :
                create_pdr_ie = \
                        IE_CreatePDR(IE_list = [
                                IE_PDR_Id(id = 65535),
                                IE_Precedence(precedence = 65535),
                                IE_PDI(IE_list = [
                                    IE_SourceInterface(interface = "Access"),
                                    ]),
                                IE_FAR_Id(id = 65535),
                        ])

                create_far_ie = \
                        IE_CreateFAR(IE_list = [
                                IE_FAR_Id(id = 65535),
                                IE_ApplyAction(FORW = 1),
                                IE_ForwardingParameters(IE_list = [
                                    IE_DestinationInterface(interface = "SGi-LAN/N6-LAN"),
                                    IE_HeaderEnrichment(
                                            header_type = 'HTTP',
                                            name = 'x-supi',
                                            value = 'imsi-001010000000001',
                                            extra_data = 'raw data'
                                            )
                                ])
                        ])

                return {'PDR' : create_pdr_ie, 'FAR' : create_far_ie}

        def gen_pfcp_session_establishment_request(self) :
                qers = []
                ambr_qer_id, ambr_qer = self._gen_qer(
                                mbr = {'ul' : 80000, 'dl' : 80000})
                qers.append(ambr_qer)

                qos_flow_1_qer_id, qos_flow_1_qer = self._gen_qer(
                                mbr = {'ul' : 80000, 'dl' : 80000})
                qers.append(qos_flow_1_qer)

                qos_flow_2_qer_id, qos_flow_2_qer = self._gen_qer(
                                mbr = {'ul' : 80000, 'dl' : 80000})
                qers.append(qos_flow_2_qer)

                sdf1_qer_id, sdf1_qer = self._gen_qer(
                                mbr = {'ul' : 80000, 'dl' : 80000})
                qers.append(sdf1_qer)

                gbr_qer_id, gbr_qer = self._gen_qer(
                                mbr = {'ul' : 80000, 'dl' : 80000},
                                gbr = {'ul' : 80000, 'dl' : 80000})
                qers.append(gbr_qer)

                #sdf1 = self._gen_sdf_flow_description(
                #                'permit out ip from 172.16.24.1 to any')
                sdf1 = self._gen_sdf_flow_description(
                                'permit out ip from 1.1.1.1 to any')
                #sdf2 = self._gen_sdf_flow_description(
                #                'permit out ip from 172.16.24.2 to any')
                sdf2 = self._gen_sdf_flow_description(
                                'permit out ip from 1.1.1.1 to any')
                #sdf3 = self._gen_sdf_flow_description(
                #                'permit out ip from 172.16.24.3 to any')
                sdf3 = self._gen_sdf_flow_description(
                                'permit out ip from 1.1.1.1 to any')

                tf = self._gen_traffic_endpoint()
                tf_id = {'ul' : tf['N3']['id'], 'dl' : tf['N6']['id']}

                flows = [
                        # gbr
                        self._gen_flow([gbr_qer_id], tf_id, sdf1),
                        #self._gen_flow([gbr_qer_id], tf_id),
                        # ambr -> qos 1
                        #self._gen_flow([ambr_qer_id, qos_flow_1_qer_id], tf_id, sdf2),
                        #self._gen_flow([ambr_qer_id, qos_flow_1_qer_id], tf_id),
                        # ambr -> qos 2 -> sdf 1
                        #self._gen_flow([ambr_qer_id, qos_flow_2_qer_id, sdf1_qer_id], 
                        #                tf_id, sdf3),
                        #self._gen_flow([ambr_qer_id, qos_flow_2_qer_id, sdf1_qer_id], 
                        #                tf_id),
                        # ambr
                        #self._gen_flow([ambr_qer_id], tf_id),
                ]

                enrichment_ie = self._gen_header_enrichment()

                ie_list = [IE_NodeId(id_type = 'FQDN', id = self._conf['NodeId']),
                                IE_FSEID(v4 = 1, ipv4 = self._host, seid = 999)]

                for flow in flows :
                        ie_list.append(flow['UL']['PDR'])
                        ie_list.append(flow['DL']['PDR'])
                ie_list.append(enrichment_ie['PDR'])

                for flow in flows : 
                        ie_list.append(flow['UL']['FAR'])
                        ie_list.append(flow['DL']['FAR'])
                ie_list.append(enrichment_ie['FAR'])

                for qer in qers :
                        ie_list.append(qer)

                ie_list.append(tf['N3']['ie'])
                ie_list.append(tf['N6']['ie'])

                pfcp_ie = \
                        PFCP(message_type = 'session_establishment_request', S = 1, seid = 0,
                                        seq = self.seq_num)/\
                        PFCPSessionEstablishmentRequest(IE_list = ie_list)

                return bytes(pfcp_ie)

        def gen_pfcp_session_modification_request(self, seid) :
                update_far = []
                for far_id in range(2, self._pdr_far_id+1, 2) :
                        update_far.append(\
                                IE_UpdateFAR(IE_list = [
                                        IE_FAR_Id(id = far_id),
                                        IE_ApplyAction(FORW = 1),
                                        IE_UpdateForwardingParameters(IE_list = [
                                            IE_DestinationInterface(interface = "Access"),
                                            IE_NetworkInstance(instance = 'N6'),
                                            IE_OuterHeaderCreation(
                                                    GTPUUDPIPV4 = 1, 
                                                    TEID = 1,
                                                    ipv4 = "172.16.27.1",
                                                    ),
                                            ]),
                                        IE_3GPP_InterfaceType(interface_type = 'N3 3GPP Access')
                                ])
                                )

                pfcp_ie = \
                        PFCP(message_type = 'session_modification_request', S = 1, seid = seid,
                                seq = self.seq_num)/\
                        PFCPSessionModificationRequest(IE_list = update_far)

                return bytes(pfcp_ie)

        def gen_pfcp_session_deletion_request(self, seid) :
                pfcp_ie = \
                        PFCP(message_type = 'session_deletion_request', S = 1, seid = seid,
                                seq = self.seq_num)/\
                        PFCPSessionDeletionRequest()

                return bytes(pfcp_ie)

        def gen_pfcp_association_setup_request(self) :
                pfcp_ie = \
                        PFCP(message_type = "association_setup_request", S = 0, 
                                seq = self.seq_num)/\
                        PFCPAssociationSetupRequest(IE_list = [
                                IE_NodeId(id_type = 'FQDN', id = self._conf['NodeId']),
                                IE_RecoveryTimeStamp(timestamp = timestamp()),
                                IE_CPFunctionFeatures_r16(SSET = 1, BUNDL = 1)
                        ])

                return bytes(pfcp_ie)

        # Copy from keysight
        def gen_pfcp_association_release_request(self) :
                pfcp_ie = \
                        PFCP(message_type = "association_release_request", S = 0, 
                                        seq = self.seq_num)/\
                        PFCPAssociationReleaseRequest(IE_list = [
                                IE_NodeId(id_type = 'FQDN', id = self._conf['NodeId']),
                        ])

                return bytes(pfcp_ie)

        def gen_pfcp_heartbeat_request(self) :
                pfcp_ie = \
                        PFCP(message_type = "heartbeat_request", S = 0, 
                                        seq = self.seq_num)/\
                        PFCPHeartbeatRequest(IE_list = [
                                IE_Source_IP_Address_r16(V4 = 1, ipv4 = self._host),
                                IE_RecoveryTimeStamp(timestamp = timestamp())
                        ])

                return bytes(pfcp_ie)

class QosTestCase(unittest.TestCase) :
    def setUp(self) :
        host = '127.0.0.1'
        #host = '172.16.27.4'
        port = 8805
        self.smf = SMF(host, port)
        self.log = False
        self.seids = []
        self.session_num = 1

    def tearDown(self) :
        self.smf = None

    def association_setup(self) :
        pfcp_ie = self.smf.gen_pfcp_association_setup_request()
        cause = self.smf.send_request(pfcp_ie)
        self.assertEqual(CauseValues[cause], 'Request accepted')
        if self.log :
            print('PFCPAssociationSetupResponse : {}'.format(CauseValues[cause]))

    def heartbeat(self) :
        pfcp_ie = self.smf.gen_pfcp_heartbeat_request()
        t = self.smf.send_request(pfcp_ie)
        self.assertGreaterEqual(timestamp(), t)
        if self.log :
            print('PFCPHeartbeatResponse : recovery timestamp {}'.format(t))

    def session_establishment_modification(self) :
        self.seids = []
        for j in range(0, self.session_num) :
            pfcp_ie = self.smf.gen_pfcp_session_establishment_request()
            cause, seid = self.smf.send_request(pfcp_ie)
            self.assertEqual(CauseValues[cause], 'Request accepted')
            self.assertGreaterEqual(seid, 0)
            if self.log :
                print('[{}] PFCPSessionEstablishmentResponse : {}'.format(
                        seid, CauseValues[cause]))

            pfcp_ie = self.smf.gen_pfcp_session_modification_request(seid)
            cause = self.smf.send_request(pfcp_ie)
            self.assertEqual(CauseValues[cause], 'Request accepted')
            if self.log :
                print('[{}] PFCPSessionModificationResponse : {}'.format(
                    seid, CauseValues[cause]))

            self.seids.append(seid) 

    def session_deletion(self) :
        for seid in self.seids :
            pfcp_ie = self.smf.gen_pfcp_session_deletion_request(seid)
            cause = self.smf.send_request(pfcp_ie)
            self.assertEqual(CauseValues[cause], 'Request accepted')
            if self.log :
                print('[{}] PFCPSessionDeletionResponse : {}'.format(
                    seid, CauseValues[cause]))

    def association_release(self) :
        pfcp_ie = self.smf.gen_pfcp_association_release_request()
        cause = self.smf.send_request(pfcp_ie)
        self.assertEqual(CauseValues[cause], 'Request accepted')
        if self.log :
            print('PFCPAssociationReleaseResponse : {}'.format(CauseValues[cause]))

def main() :
    tests = [
            'association_setup', 
            'heartbeat',
            'session_establishment_modification',
            # 'session_deletion',
            # 'association_release'
            ]

    suite = unittest.TestSuite(map(QosTestCase, tests))
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == '__main__' :
    main()
