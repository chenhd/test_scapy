import struct
import datetime

import netifaces
from scapy.all import *

from ConstantValue import ProtocolHeaderLength, S2C_CMD_PB, \
    ProtocolHeaderLength_Cmd, ProtocolHeaderLength_DataLen, C2S_CMD_PB
from protobuf.cmd_pb2 import *
from protobuf.main_pb2 import *


# import winreg
# from scapy.arch.windows import sniff
# from scapy.sendrecv import sniff
# from scapy.all import *
# server_ip = '10.11.66.32'

# cn
# server_ip = '10.11.81.132'
# vn
server_ip = '10.11.81.132'

if __name__ == '__main__':
    iface_guids = netifaces.interfaces()
    for i in iface_guids:
        print i, '|', 
    print 
 
    iface_names = ['(unknown)' for i in range(len(iface_guids))]
#     reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
#     reg_key = winreg.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
#     for i in range(len(iface_guids)):
#         try:
#             reg_subkey = winreg.OpenKey(reg_key, iface_guids[i] + r'\Connection')
#             iface_names[i] = winreg.QueryValueEx(reg_subkey, 'Name')[0]
#         except Exception as e:
#             pass
     
    for i in iface_names:
        print i, '|', 
    print
    print '*' * 50
    
    def _callback(ether_data):
#         ether_data.show()
#         print '-' * 50
#         data.summary()
#         print data.sniffed_on
#         print ether_data.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}")
#         Ether | IP | TCP | Raw
        res = ether_data.payload.payload.payload.original
#         print res
        
        
        
        
#         first_byte = struct.unpack('B', res[0])[0]
        if res == '':
            return
        first_byte = struct.unpack('B', res[0])[0]
#         not websocket package: http
        if first_byte != 130:
            return
#             continue
#         first byte([0]) dont have change
        
#         server_ip = '10.11.66.32'
        if ether_data.payload.fields['src'] == server_ip:
            target = 'recv'
            print 'recv', datetime.now().strftime("%H:%M:%S")
#             target = 'send'
#             print 'send'
        else:
            target = 'send'
            print 'send', datetime.now().strftime("%H:%M:%S")
#             target = 'recv'
#             print 'recv'
#         print ether_data.sprintf("{IP:%IP.src% -> %IP.dst%}")
        
        offset = 1
        
        second_byte = struct.unpack('B', res[offset])[0]
        isMask = second_byte >> 7 == 1
        offset += 1
        
#         if 0 <= length <= 125, you don't need additional bytes
#         if 126 <= length <= 65535, you need two additional bytes and the second byte is 126
#         if length >= 65536, you need eight additional bytes, and the second byte is 127
        length = second_byte & 0b01111111
        if length == 126:
            length = struct.unpack('>H', res[offset:offset+2])[0]
            offset += 2
        
        if isMask:
            MaskingKey = res[offset:offset+4]
            offset += 4
        
#         ws data package:result_data
        result_data = res[offset:]
        
        result_data = bytearray(result_data)
        
        if isMask:
#             decode !!
            MaskingKey = bytearray(MaskingKey)
            for i in range(len(result_data)):
                result_data[i] = result_data[i] ^ MaskingKey[i%4]
            
            
        payload = struct.pack('%dB'%(len(result_data)), *result_data)
        
        while len(payload) >= ProtocolHeaderLength:
            data_len, protocol_cmd = struct.unpack('<hh', payload[:ProtocolHeaderLength])
            if protocol_cmd == 212:
                pass
            if protocol_cmd == 32674:
                pass
            if data_len == 2:
                print target, 'protocol_cmd:', protocol_cmd
                print
            elif target == 'recv':
                if S2C_CMD_PB.has_key(protocol_cmd):
                    pb = S2C_CMD_PB[protocol_cmd]
#                     print pb.__class__.__name__, protocol_cmd, ":\n",
                    try:
                        pb = pb()
                        pb.ParseFromString(payload[ProtocolHeaderLength:ProtocolHeaderLength+data_len-ProtocolHeaderLength_Cmd])
                    except Exception as e:
                        print target, "parse fail!!!!!!", protocol_cmd, data_len
                        pass
                    if False:
                        pass
                    elif protocol_cmd == S2C_Ping:
                        pass
                    elif protocol_cmd == S2C_Run:
                        pass
                    else:
                        print ether_data.sprintf("{IP:%IP.src% -> %IP.dst%\n}{TCP:%TCP.sport% -> %TCP.dport%\n}")
                        print pb.__class__.__name__, protocol_cmd, ":\n", pb
                        pass
                    
#                     print pb
                else:
                    print ether_data.sprintf("{IP:%IP.src% -> %IP.dst%\n}{TCP:%TCP.sport% -> %TCP.dport%\n}")
                    print "recv undo protocol cmd: " + str(protocol_cmd), ProtocolHeaderLength, ProtocolHeaderLength+data_len-ProtocolHeaderLength_Cmd, data_len, ProtocolHeaderLength_Cmd
                    print
            elif target == 'send':
                if C2S_CMD_PB.has_key(protocol_cmd):
                    pb = C2S_CMD_PB[protocol_cmd]
                    if pb:
                        pb = pb()
#                     print pb.__class__.__name__, protocol_cmd, ":\n",
                        pb.ParseFromString(payload[ProtocolHeaderLength:ProtocolHeaderLength+data_len-ProtocolHeaderLength_Cmd])
                    if False:
                        pass
                    elif protocol_cmd == C2S_Ping:
                        pass
#                     elif protocol_cmd == C2S_ChangeSkillSlot:
#                         pass
#                     elif protocol_cmd == C2S_AoeSkill:
#                         pass
#                     elif protocol_cmd == C2S_CharSkill:
#                         pass
#                     elif protocol_cmd == C2S_DirSkill:
#                         pass
#                     elif protocol_cmd == C2S_Stand:
#                         pass
#                     elif protocol_cmd == C2S_Run:
#                         pass
#                     elif protocol_cmd == C2S_Chat:
#                         print 1
#                         pass
                    else:
                        print ether_data.sprintf("{IP:%IP.src% -> %IP.dst%\n}{TCP:%TCP.sport% -> %TCP.dport%\n}")
                        print pb.__class__.__name__, protocol_cmd, ":\n", pb
                        
#                     print pb
                else:
                    print ether_data.sprintf("{IP:%IP.src% -> %IP.dst%\n}{TCP:%TCP.sport% -> %TCP.dport%\n}")
                    print "send undo protocol cmd: " + str(protocol_cmd)
                    print
            else:
                print '???'
#             print len(payload), ProtocolHeaderLength_DataLen+data_len
            payload = payload[ProtocolHeaderLength_DataLen+data_len:]
        
#         print offset
        
        pass
        
        print '-' * 50
        
        
        
        
        
        
        
    
    sniff(
#         iface=iface_guids[0],
#         iface=iface_guids[1],
#         filter="tcp",
        filter="tcp and host " + server_ip,
#         filter="tcp and host " + server_ip + " or 10.11.66.32",
#         filter="tcp and host 10.11.66.32 and port 10201",
        prn=_callback,
        )
#     sniff(prn = lambda x: x.show(), filter="tcp", store=0)
#     sniff(iface=iface_guids[0], prn = lambda x: x.show(), filter="tcp", store=0)
#     sniff(iface=iface_guids[1], prn = lambda x: x.show(), filter="tcp", store=0)
