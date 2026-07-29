import nmap
import json
import os
import time
import requests

TOKEN_TELEGRAM = os.environ["TOKEN_TELEGRAM"]
CHAT_ID = os.environ["CHAT_ID"]
SUBNET_RETEA = os.environ.get("SUBNET_RETEA", "192.168.1.0/24")

FISIER_DUMMY = "dispozitive_cunoscute.json"
INTERVAL_SCANARE = 300

def trimite_telegram(mesaj):
    url = f"https://api.telegram.org/bot{TOKEN_TELEGRAM}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": mesaj, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload)
    except Exception as e:
        print(f"Eroare la trimiterea mesajului pe Telegram: {e}")

def scaneaza_retea():
    nm = nmap.PortScanner()
    print("[+] Se rulează scanarea de rețea (Ping Sweep)...")
    nm.scan(hosts=SUBNET_RETEA, arguments='-sn')
    
    dispozitive = {}
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            mac = nm[host]['addresses']['mac']
            vendor = nm[host]['vendor'].get(mac, "Unknown Vendor")
            dispozitive[mac] = {
                "ip": host,
                "vendor": vendor
            }
    return dispozitive

def scanare_detaliata_host(ip):
    nm = nmap.PortScanner()
    print(f"[+] Scanare profundă porturi pentru IP: {ip}")
    nm.scan(hosts=ip, arguments='-F -sV')
    raport = []
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            lport = nm[ip][proto].keys()
            for port in lport:
                stare = nm[ip][proto][port]['state']
                serviciu = nm[ip][proto][port]['name']
                versiune = nm[ip][proto][port]['product']
                raport.append(f"  - Port {port}/{proto}: {stare} ({serviciu} {versiune})")
    return "\n".join(raport) if raport else "  - Nu s-au găsit porturi deschise la scanarea rapidă."

def main():
    print("[*] Drop Box pornit cu succes.")
    trimite_telegram("🤖 *Sistemul Drop Box RPi5 (P1) a pornit și monitorizează rețeaua!*")

    while True:
        dispozitive_curente = scaneaza_retea()
        
        if not os.path.exists(FISIER_DUMMY):
            with open(FISIER_DUMMY, "w") as f:
                json.dump(dispozitive_curente, f, indent=4)
            print("[+] Whitelist inițial salvat.")
            trimite_telegram(f"📋 *Whitelist inițial creat.* S-au detectat {len(dispozitive_curente)} dispozitive de încredere.")
        else:
            with open(FISIER_DUMMY, "r") as f:
                dispozitive_cunoscute = json.load(f)
            
            for mac, info in dispozitive_curente.items():
                if mac not in dispozitive_cunoscute:
                    print(f"[ALERTĂ] Dispozitiv nou detectat: {mac}")
                    
                    mesaj_alerta = (
                        f"⚠️ *DISPOZITIV NOU DETECTAT ÎN REȚEA!*\n\n"
                        f"📍 *IP:* `{info['ip']}`\n"
                        f"🛡️ *MAC:* `{mac}`\n"
                        f"🏭 *Vendor:* `{info['vendor']}`\n"
                        f"⏱️ Se începe scanarea detaliată de porturi...\n"
                    )
                    trimite_telegram(mesaj_alerta)
                    
                    detalii_porturi = scanare_detaliata_host(info['ip'])
                    mesaj_porturi = f"🔍 *Raport Porturi active pentru {info['ip']}:*\n{detalii_porturi}"
                    trimite_telegram(mesaj_porturi)
                    
                    dispozitive_cunoscute[mac] = info
            
            with open(FISIER_DUMMY, "w") as f:
                json.dump(dispozitive_cunoscute, f, indent=4)
                
        time.sleep(INTERVAL_SCANARE)

if __name__ == "__main__":
    main()
