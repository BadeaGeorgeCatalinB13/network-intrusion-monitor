import time
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd

INTERFATA = "wlan0"
INTERVAL_COLECTARE = 10
FISIER_SALVARE = "trafic_normal.csv"
DATE_COLECTATE = []

pachete_curente = 0
biti_curenti = 0
porturi_unice = set()
ip_uri_unice = set()
tcp_count = 0
udp_count = 0

def proceseaza_pachet(pkt):
    global pachete_curente, biti_curenti, tcp_count, udp_count
    pachete_curente += 1
    biti_curenti += len(pkt)
    if IP in pkt:
        ip_uri_unice.add(pkt[IP].src)
        ip_uri_unice.add(pkt[IP].dst)
    if TCP in pkt:
        tcp_count += 1
        porturi_unice.add(pkt[TCP].sport)
        porturi_unice.add(pkt[TCP].dport)
    elif UDP in pkt:
        udp_count += 1
        porturi_unice.add(pkt[UDP].sport)
        porturi_unice.add(pkt[UDP].dport)

def salveaza_fereastra_timp():
    global pachete_curente, biti_curenti, tcp_count, udp_count
    global porturi_unice, ip_uri_unice, DATE_COLECTATE
    if pachete_curente == 0:
        return
    features = {
        "packet_count": pachete_curente,
        "byte_count": biti_curenti,
        "unique_ips": len(ip_uri_unice),
        "unique_ports": len(porturi_unice),
        "tcp_ratio": tcp_count / pachete_curente if pachete_curente > 0 else 0,
        "udp_ratio": udp_count / pachete_curente if pachete_curente > 0 else 0
    }
    DATE_COLECTATE.append(features)
    pachete_curente = 0
    biti_curenti = 0
    tcp_count = 0
    udp_count = 0
    porturi_unice.clear()
    ip_uri_unice.clear()
    df = pd.DataFrame(DATE_COLECTATE)
    df.to_csv(FISIER_SALVARE, index=False)
    print(f"[+] Fereastra {len(DATE_COLECTATE)}/30 salvată.")

def main():
    print("[*] Începe colectarea datelor de bază...")
    while len(DATE_COLECTATE) < 30:
        sniff(iface=INTERFATA, timeout=INTERVAL_COLECTARE, prn=proceseaza_pachet, store=False)
        salveaza_fereastra_timp()
    print("[*] Colectare finalizată! Fișierul trafic_normal.csv a fost generat.")

if __name__ == "__main__":
    main()
