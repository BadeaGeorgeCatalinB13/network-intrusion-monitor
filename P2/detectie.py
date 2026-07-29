import time
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib

INTERFATA = "wlan0"
INTERVAL_DETECTIE = 10
MODEL_PATH = "model_anomalii.joblib"

model = joblib.load(MODEL_PATH)
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

def ruleaza_predictie():
    global pachete_curente, biti_curenti, tcp_count, udp_count
    global porturi_unice, ip_uri_unice
    if pachete_curente == 0:
        return
    features = {
        "packet_count": [pachete_curente],
        "byte_count": [biti_curenti],
        "unique_ips": [len(ip_uri_unice)],
        "unique_ports": [len(porturi_unice)],
        "tcp_ratio": [tcp_count / pachete_curente if pachete_curente > 0 else 0],
        "udp_ratio": [udp_count / pachete_curente if pachete_curente > 0 else 0]
    }
    df = pd.DataFrame(features)
    predictie = model.predict(df)[0]
    if predictie == -1:
        print(f"⚠️ [ALERTĂ ML] Trafic anormal detectat! Pachete: {pachete_curente}, Octeți: {biti_curenti}, IP-uri unice: {len(ip_uri_unice)}")
    else:
        print(f"[+] Trafic normal. Pachete procesate: {pachete_curente}")
    pachete_curente = 0
    biti_curenti = 0
    tcp_count = 0
    udp_count = 0
    porturi_unice.clear()
    ip_uri_unice.clear()

def main():
    print("[*] Detectorul de anomalii ML rulează live...")
    while True:
        sniff(iface=INTERFATA, timeout=INTERVAL_DETECTIE, prn=proceseaza_pachet, store=False)
        ruleaza_predictie()

if __name__ == "__main__":
    main()
