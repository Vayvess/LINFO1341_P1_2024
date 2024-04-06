import pyshark
from collections import defaultdict

class Analyzer:
    def __init__(self, fpath) -> None:
        self.capture = pyshark.FileCapture(fpath)
    
    def sandbox(self):
        lens = defaultdict(int)
        infos = defaultdict(lambda: (0, 0, []))
        TLSCOUNT = 0
        for pkt in self.capture:
            try:
                ip_src, ip_dst, port_src, port_dst, protocole = None, None, None, None, None
                # Vérifier si le paquet est IP (cela inclut IPv4 et IPv6)
                if 'IP' in pkt:
                    ip_src = pkt.ip.src
                    ip_dst = pkt.ip.dst
                    protocole = 'IP'

                # Vérifier si le paquet est TCP ou UDP pour extraire les ports
                if 'TCP' in pkt:
                    port_src = pkt.tcp.srcport
                    port_dst = pkt.tcp.dstport
                    protocole = 'TCP'
                elif 'UDP' in pkt:
                    port_src = pkt.udp.srcport
                    port_dst = pkt.udp.dstport
                    protocole = 'UDP'
                
                # Ajouter les informations extraites à l'ensemble
                if ip_src and ip_dst:
                    t = (ip_src, ip_dst, port_src, port_dst, protocole)
                    npacket, total, listing = infos[t]
                    listing.append(pkt)
                    if t == ('192.168.0.10', '45.157.188.28', '45338', '443', 'TCP'):
                        lens[len(pkt)] += 1
                        if 'TLS' in pkt:
                            TLSCOUNT += 1
                    infos[t] = (npacket + 1, total + len(pkt), listing)
            except AttributeError:
                pass
        
        
        with open("stats.txt", "w") as f:
            for k, v in infos.items():
                f.write(f"{k}, {v[0]}, {v[1]}\n")
        
        # with open("focus.txt", "w") as f:
        #     t = ('192.168.0.10', '45.157.188.28', '45338', '443', 'TCP')
        #     for packet in infos[t][2]:
        #         print(packet)
        #         print()

        # for k, v in lens.items():
        #     print(k, v)
        print(TLSCOUNT)


analyzer = Analyzer('video_upload_trace.pcapng')
analyzer.sandbox()
