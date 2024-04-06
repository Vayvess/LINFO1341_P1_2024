import pyshark
from collections import defaultdict

class Analyzer:
    def __init__(self, fpath):
        self.capture = pyshark.FileCapture(fpath)
    
    def enumerate_exchange(self):
        timer = 0
        infos = defaultdict(lambda: (-1, 0, 0, []))
        for pkt in self.capture:
            try:
                ip_src, ip_dst, port_src, port_dst, protocole = None, None, None, None, None
                if 'IP' in pkt:
                    ip_src = pkt.ip.src
                    ip_dst = pkt.ip.dst
                    protocole = 'IP'
                
                if 'TCP' in pkt:
                    port_src = pkt.tcp.srcport
                    port_dst = pkt.tcp.dstport
                    protocole = 'TCP'
                elif 'UDP' in pkt:
                    port_src = pkt.udp.srcport
                    port_dst = pkt.udp.dstport
                    protocole = 'UDP'
                
                if ip_src and ip_dst:
                    t = (ip_src, ip_dst, port_src, port_dst, protocole)
                    curr_timer, npacket, total, listing = infos[t]
                    listing.append(pkt)
                    if curr_timer == -1:
                        curr_timer = timer
                        timer += 1
                    infos[t] = (curr_timer, npacket + 1, total + len(pkt) - 16, listing)
            except AttributeError:
                pass

        for k, v in infos.items():
            print(k, f"\ntimer: {v[0]}\npkt ammount: {v[1]}\nexchange size: {v[2]}")
            print()

analyzer = Analyzer('ksync_trace.pcapng')
analyzer.enumerate_exchange()
