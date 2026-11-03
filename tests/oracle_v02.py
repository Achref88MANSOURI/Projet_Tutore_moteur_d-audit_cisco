"""Expected values transcribed from original Cisco lines, not parser output.

No parser or normalizer imports. Host/interface facts were read from the 20
immutable config copies; advanced facts include prior failure cases.
"""
FACTS=[]
def add(fid,line,source,native,selectors,field,value):
    FACTS.append(dict(file_id=fid,line=line,source=source,native=native,selectors=selectors,field=field,expected=value))
HOSTS=[('F0456',25,'rt1.bsqmk'),('F0457',25,'rt1.thdo'),('F0001',7,'as1border1'),('F0004',7,'as2border1'),('F0011',7,'as3border1'),
 ('F0003',7,'as1core1'),('F0008',7,'as2dept1'),('F0057',13,'R-PrivateASN100'),('F0059',13,'R-PublicASN111'),('F0049',12,'R1'),('F0053',12,'R3'),('F0055',13,'R4'),
 ('F0405',15,'PE-1'),('F0406',15,'PE-2'),('F0291',14,'PE-1'),('F0344',15,'PE-1'),('F0371',15,'PE-1'),('F0372',15,'PE-2'),('F0409',12,'R1'),('F0410',12,'R2')]
for fid,line,name in HOSTS:add(fid,line,'hostname '+name,{'hostname':name},[],'system/identity/hostname',name)
INTERFACES=[('F0456',85,'GigabitEthernet0/1','negotiation auto'),('F0457',72,'GigabitEthernet0/1','negotiation auto'),
 ('F0001',62,'GigabitEthernet0/0','speed 1000'),('F0004',69,'GigabitEthernet0/0','speed 1000'),('F0011',65,'GigabitEthernet0/0','speed 1000'),('F0003',65,'GigabitEthernet0/0','speed 1000'),('F0008',62,'GigabitEthernet0/0','speed 1000'),
 ('F0057',155,'GigabitEthernet1','negotiation auto'),('F0059',148,'GigabitEthernet1','negotiation auto'),('F0405',194,'GigabitEthernet1','negotiation auto'),('F0406',193,'GigabitEthernet1','negotiation auto'),
 ('F0291',194,'GigabitEthernet1','negotiation auto'),('F0344',182,'GigabitEthernet1','negotiation auto'),('F0371',213,'GigabitEthernet1','negotiation auto'),('F0372',212,'GigabitEthernet1','negotiation auto')]
for fid,line,interface,command in INTERFACES:
    if command=='speed 1000':field='speed_bps';native={'speed':'1000'};expected=1000000000
    else:field='negotiation';native={'negotiation':'auto'};expected='auto'
    add(fid,line,command,native,[('interfaces',{'name':interface})],'ethernet/'+field,expected)
EMPTY=[('F0456',98,'GigabitEthernet0/2'),('F0457',67,'GigabitEthernet0/1'),('F0001',55,'Ethernet0/0'),('F0004',60,'Ethernet0/0'),('F0011',58,'Ethernet0/0'),
 ('F0003',58,'Ethernet0/0'),('F0008',55,'Ethernet0/0'),('F0057',160,'GigabitEthernet2'),('F0059',153,'GigabitEthernet2'),('F0049',135,'FastEthernet2/0'),('F0053',90,'FastEthernet2/0'),
 ('F0055',81,'FastEthernet1/1'),('F0291',201,'GigabitEthernet2'),('F0344',190,'GigabitEthernet2'),('F0409',94,'GigabitEthernet0/3'),('F0410',94,'GigabitEthernet0/3')]
for fid,line,interface in EMPTY:add(fid,line,'no ip address',{'empty':True},[('interfaces',{'name':interface})],'ipv4/addresses',[])
BGP=[('routing/bgp',{'local_as':1,'network_instance':None})]
add('F0001',90,'neighbor 1.10.1.1 update-source Loopback0',{'peer':'1.10.1.1','source':'Loopback0'},BGP+[('neighbors',{'peer':'1.10.1.1','kind':'neighbor'})],'update_source','Loopback0')
add('F0001',109,'neighbor 1.10.1.1 activate',{'peer':'1.10.1.1','enabled':True},BGP+[('address_families',{'afi':'ipv4'}),('peers',{'peer':'1.10.1.1','kind':'neighbor'})],'active',True)
add('F0001',104,'neighbor as2 route-map as2_to_as1 in',{'peer':'as2','policy':'as2_to_as1','direction':'in'},BGP+[('address_families',{'afi':'ipv4'}),('peers',{'peer':'as2','kind':'group'})],'import_policies',['as2_to_as1'])
add('F0001',101,'neighbor as1 send-community',{'peer':'as1','option':'unspecified'},BGP+[('address_families',{'afi':'ipv4'}),('peers',{'peer':'as1','kind':'group'})],'send_community','command_without_option')
add('F0001',113,'maximum-paths eibgp 5',{'type':'eibgp','count':5},BGP+[('address_families',{'afi':'ipv4'})],'maximum_paths',[{'type':'eibgp','count':5}])
for version,line in [(2,147),(3,194)]:add('F0049',line,'router-id 121.0.0.1',{'router_id':'121.0.0.1'},[('routing/ospf',{'identifier':'1','version':version})],'router_id','121.0.0.1')
add('F0049',195,'area 1 virtual-link 121.0.0.3',{'area':'1','peer':'121.0.0.3'},[('routing/ospf',{'identifier':'1','version':3})],'virtual_links',[{'area':'0.0.0.1','peer_router_id':'121.0.0.3','authentication':None}])
add('F0049',200,'mpls ldp router-id Loopback0 force',{'interface':'Loopback0','option':'force'},[],'mpls/ldp/force',True)
add('F0291',256,'mpls ldp router-id Loopback0',{'interface':'Loopback0'},[],'mpls/ldp/router_id_interface','Loopback0')
add('F0049',226,'transport input all',{'transports':'all'},[('system/management/lines',{'name':'vty 0 4'})],'allowed_transports',['all'])
add('F0456',73,'tunnel destination 195.177.253.41',{'destination':'195.177.253.41'},[('vpn/tunnels',{'identifier':'Tunnel0'})],'remote_endpoint','195.177.253.41')
add('F0456',72,'tunnel source Loopback0',{'source':'Loopback0'},[('vpn/tunnels',{'identifier':'Tunnel0'})],'local_endpoint','94.45.227.2')
add('F0456',208,'ip prefix-list Nothing deny 0.0.0.0/0 le 32',{'name':'Nothing','action':'deny','prefix':'0.0.0.0/0','le':32},[('routing_policies/prefix_lists',{'name':'Nothing','family':'ipv4'})],'entries',[{'sequence':None,'action':'deny','prefix':'0.0.0.0/0','ge':None,'le':32}])
add('F0456',221,'ipv6 prefix-list Nothing seq 5 deny ::/0 le 128',{'name':'Nothing','sequence':5,'action':'deny','prefix':'::/0','le':128},[('routing_policies/prefix_lists',{'name':'Nothing','family':'ipv6'})],'entries',[{'sequence':5,'action':'deny','prefix':'::/0','ge':None,'le':128}])
add('F0371',170,'match dscp ef',{'dscp':'ef'},[('qos/class_maps',{'name':'VOICE'})],'matches',[{'kind':'dscp','value':'ef','address_family':None}])
add('F0371',182,'set dscp ef',{'dscp':'ef'},[('qos/policy_maps',{'name':'VOICE-QOS-CUST-A'}),('classes',{'name':'VOIP-CUST-A'})],'actions',[{'kind':'set_dscp','value':'ef'}])

# Human scope correction: no extension to previously unmatched commands.
for fact in FACTS:
    if (fact['file_id'],fact['line']) in {('F0291',256),('F0344',202),('F0344',203)}:fact['deferred']=True
