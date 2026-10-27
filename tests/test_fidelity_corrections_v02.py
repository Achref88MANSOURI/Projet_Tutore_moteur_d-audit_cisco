"""Source-led regression expectations; no production mapper helpers as oracles."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

import pytest

from normalizer.v02 import SemanticMapper
from parser.run_ttp import extract
from parser.coverage_v02 import build_coverage
from schemas import normalizedconfig_v02 as contract

ROOT=Path(__file__).resolve().parents[1]


def normalize(text):
    extracted=extract(text,official=False)
    mapper=SemanticMapper(extracted,text,'fidelity.cfg','ios',hashlib.sha256(text.encode()).hexdigest())
    document=mapper.run()
    return document,build_coverage(extracted,mapper)


def selected(items,**identity):
    found=[x for x in items if all(getattr(x,k)==v for k,v in identity.items())]
    assert len(found)==1,identity
    return found[0]


@pytest.mark.parametrize('peer,expected_peer,group',[
    ('192.0.2.1','192.0.2.1',False),
    ('2001:DB8::A','2001:db8::a',False),
    ('UPSTREAM','UPSTREAM',True),
])
def test_remote_as_native_identity_integer_and_status(peer,expected_peer,group):
    definition=f' neighbor {peer} peer-group\n' if group else ''
    text=f'router bgp 65000\n{definition} neighbor {peer} remote-as 65001\n'
    n,c=normalize(text)
    process=selected(n.configuration.routing.bgp,local_as=65000,network_instance=None)
    option=selected(process.peer_options,peer=expected_peer,kind='group' if group else 'neighbor')
    assert option.remote_as==65001 and type(option.remote_as) is int
    assert c['commands'][-1]['status']=='fully_normalized'
    assert not hasattr(option,'bgp_remote_as')


def test_remote_as_asdot_is_a_scalar_asn():
    n,c=normalize('router bgp 65000\n neighbor 192.0.2.1 remote-as 1.10\n')
    assert n.configuration.routing.bgp[0].peer_options[0].remote_as==65546
    assert c['commands'][-1]['status']=='fully_normalized'


def test_remote_as_same_neighbor_distinct_vrfs_and_families():
    text=('router bgp 65000\n'
          ' neighbor 192.0.2.1 remote-as 65001\n'
          ' address-family ipv4 vrf BLUE\n'
          '  neighbor 192.0.2.1 remote-as 65002\n'
          ' exit-address-family\n'
          ' address-family ipv4 vrf RED\n'
          '  neighbor 192.0.2.1 remote-as 65003\n'
          ' exit-address-family\n'
          ' address-family ipv6\n'
          '  neighbor 2001:DB8::A remote-as 65004\n'
          '  no neighbor 2001:DB8::A activate\n'
          ' exit-address-family\n')
    n,c=normalize(text)
    for vrf,expected in [(None,65001),('BLUE',65002),('RED',65003)]:
        p=selected(n.configuration.routing.bgp,local_as=65000,network_instance=vrf)
        peers=p.peer_options if vrf is None else selected(p.family_options,afi='ipv4',safi=None).peers
        assert selected(peers,peer='192.0.2.1',kind='neighbor').remote_as==expected
        if vrf:assert p.peer_options==[]
    global_process=selected(n.configuration.routing.bgp,local_as=65000,network_instance=None)
    ipv6=selected(global_process.family_options,afi='ipv6',safi=None)
    peer=selected(ipv6.peers,peer='2001:db8::a',kind='neighbor')
    assert peer.remote_as==65004 and peer.active is False
    assert all(row['status']=='fully_normalized' for row in c['commands'] if row['line'] in (2,4,7,10,11))


@pytest.mark.parametrize('remote_as',['0','-1','4294967296','65536.0','1.65536','invalid'])
def test_invalid_asn_is_not_fully_normalized_or_invented(remote_as):
    n,c=normalize(f'router bgp 65000\n neighbor 192.0.2.1 remote-as {remote_as}\n')
    assert c['commands'][-1]['status']=='invalid_or_ambiguous'
    assert n.configuration.routing.bgp[0].peer_options==[]
    assert n.configuration.routing.bgp[0].neighbors==[]


def test_undeclared_group_is_not_guessed_or_given_full_status():
    n,c=normalize('router bgp 65000\n neighbor UNDECLARED remote-as 65001\n')
    assert n.configuration.routing.bgp[0].peer_options==[]
    assert c['commands'][-1]['status']=='invalid_or_ambiguous'


def test_primary_and_secondary_roles_are_real_booleans_and_have_source_proof():
    text=('interface GigabitEthernet1\n'
          ' ip address 192.0.2.1 255.255.255.0\n'
          ' ip address 198.51.100.1 255.255.255.0 secondary\n'
          ' no shutdown\n')
    n,c=normalize(text)
    interface=n.configuration.interfaces[0]
    assert [(str(a.address),a.prefix_length,a.secondary) for a in interface.ipv4_addresses]==[
        ('192.0.2.1',24,False),('198.51.100.1',24,True)]
    assert interface.ipv4_addresses[0].secondary is False
    assert interface.ipv4_addresses[1].secondary is True
    assert interface.admin_enabled is True
    assert all(row['status']=='fully_normalized' for row in c['commands'])
    assert any(e.path=='/configuration/interfaces/0/ipv4_addresses/0/secondary' and e.line_start==2 and e.status=='explicit' for e in n.evidence)


def test_unobserved_role_stays_null_when_migrating():
    old=json.loads((ROOT/'schemas/sample_cisco_ios.normalized.json').read_text(encoding='utf-8'))
    expected=[(i['name'],a['address']) for i in old['configuration']['interfaces'] for a in i['ipv4_addresses'] if a['secondary'] is None]
    assert expected
    migrated=contract.migrate_v01(old,ospf_version=2)
    assert [(i.name,str(a.address)) for i in migrated.configuration.interfaces for a in i.ipv4_addresses if a.secondary is None]==expected
    address=contract.v1.IPv4InterfaceAddress(address='203.0.113.1',prefix_length=24)
    assert address.secondary is None


@pytest.mark.parametrize('address,mask',[
    ('999.0.0.1','255.255.255.0'),('192.0.2.1','255.0.255.0'),
])
def test_invalid_ipv4_has_no_address_no_guessed_role_no_full_status(address,mask):
    n,c=normalize(f'interface GigabitEthernet1\n ip address {address} {mask}\n')
    assert not n.configuration.interfaces[0].ipv4_addresses
    assert c['commands'][-1]['status']=='invalid_or_ambiguous'


def test_no_address_removal_does_not_reintroduce_a_primary_address():
    n,c=normalize('interface GigabitEthernet1\n ip address 192.0.2.1 255.255.255.0\n no ip address\n')
    assert n.configuration.interfaces[0].ipv4_addresses==[]
    assert not any('/ipv4_addresses/0' in e.path for e in n.evidence)
    assert c['commands'][-1]['status']=='fully_normalized'
    assert next(r for r in c['commands'] if r['line']==2)['status']!='fully_normalized'


def test_other_partial_semantics_do_not_get_full_status_or_a_guessed_field():
    n,c=normalize('interface GigabitEthernet1\n ip pim bsr-border\n')
    assert n.configuration.interfaces[0].pim_mode is None
    assert c['commands'][-1]['status']=='extracted_unmapped'
    n,c=normalize('route-map P permit 10\n set community 65000:1 additive\n')
    assert c['commands'][-1]['status']=='extracted_unmapped'


def test_original_51_asns_and_73_primary_addresses_from_source():
    """Expected values/context come from Cisco lines, not native JSON or helpers."""
    bgp_count=primary_count=0
    for item in json.loads((ROOT/'configs/manifest.json').read_text(encoding='utf-8')):
        source=ROOT/item['config_file'];raw=source.read_bytes();text=raw.decode('utf-8-sig')
        assert hashlib.sha256(raw).hexdigest()==item['description_sha256']
        n,c=normalize(text);statuses={r['line']:r['status'] for r in c['commands']}
        root=None;af=None
        for line,rawline in enumerate(text.splitlines(),1):
            cmd=rawline.strip()
            if not cmd or cmd.startswith('!'):continue
            indent=len(rawline)-len(rawline.lstrip())
            if indent==0:root=cmd;af=None
            elif indent==1:
                af=cmd.split()[1:] if cmd.startswith('address-family ') else None
            if root and root.startswith('router bgp '):
                match=re.fullmatch(r'neighbor (\S+) remote-as (\S+)',cmd)
                if not match:continue
                local=int(root.split()[-1]);peer,remote=match.groups();parts=remote.split('.')
                expected=int(parts[0]) if len(parts)==1 else 65536*int(parts[0])+int(parts[1])
                vrf=af[af.index('vrf')+1] if af and 'vrf' in af else None
                p=selected(n.configuration.routing.bgp,local_as=local,network_instance=vrf)
                peers=selected(p.family_options,afi=af[0],safi=af[1] if len(af)>1 and af[1]!='vrf' else None).peers if af else p.peer_options
                try:identity=str(ipaddress.ip_address(peer));kind='neighbor'
                except ValueError:identity=peer;kind='group'
                assert selected(peers,peer=identity,kind=kind).remote_as==expected,(item['id'],line)
                assert statuses[line]=='fully_normalized'
                bgp_count+=1
            elif root and root.startswith('interface ') and indent==1:
                match=re.fullmatch(r'ip address (\S+) (\S+)',cmd)
                if not match:continue
                address,mask=match.groups();length=ipaddress.IPv4Network('0.0.0.0/'+mask).prefixlen
                interface=selected(n.configuration.interfaces,name=root.split()[1])
                found=[a for a in interface.ipv4_addresses if str(a.address)==address and a.prefix_length==length]
                assert len(found)==1 and found[0].secondary is False,(item['id'],line)
                assert statuses[line]=='fully_normalized'
                primary_count+=1
    assert (bgp_count,primary_count)==(51,73)
