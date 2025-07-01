from itertools import islice

from scapy.all import get_if_hwaddr, srp
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA
from scapy.layers.l2 import Ether
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import socket

from interface.interface_utils import user_select_interface, get_interface_addresses


def solicited_node_multicast(ipv6_addr: str) -> tuple[str, str]:
    """
    Verilen bir IPv6 adresinden, Neighbor Discovery için kullanılacak solicited-node multicast
    IPv6 adresi ve buna karşılık gelen multicast MAC adresini hesaplar.

    Args:
        ipv6_addr (str): Hedef IPv6 adresi (link-local olabilir, % sonrası interface dahil olabilir).

    Returns:
        tuple[str, str]: Hesaplanan multicast IPv6 adresi ve multicast MAC adresi.
    """
    # '%' sonrası arayüz bilgisi varsa kaldırılır (örn: fe80::1%eth0)
    ip = ipaddress.IPv6Address(ipv6_addr.split('%')[0])
    # IPv6 adresinin son 24 biti (3 byte) alınır
    last_24 = ip.packed[-3:]
    # Solicited-node multicast IPv6 adresi, ff02::1:ffXX:XXXX formatında hesaplanır
    multicast_ip = ipaddress.IPv6Address('ff02::1:ff00:0') + int.from_bytes(last_24, 'big')
    # Multicast MAC adresi ise 33:33:ff:XX:XX:XX formatındadır
    multicast_mac = f"33:33:ff:{last_24[0]:02x}:{last_24[1]:02x}:{last_24[2]:02x}"
    return str(multicast_ip), multicast_mac


def ipv6_nd_scan_single(interface: str, target_ip: str, src_ip: str, src_mac: str, timeout=1) -> list[dict]:
    """
    Tek bir hedef IPv6 adresine Neighbor Solicitation (NS) paketi gönderir ve
    yanıtları (Neighbor Advertisement - NA) döner.

    Args:
        interface (str): Ağ arayüzü adı (örn: eth0).
        target_ip (str): Tarama yapılacak hedef IPv6 adresi.
        src_ip (str): Kaynak IPv6 adresi (genellikle link-local).
        src_mac (str): Kaynak MAC adresi.
        timeout (int): Yanıt bekleme süresi (saniye).

    Returns:
        list[dict]: Yanıt veren cihazların IP ve MAC adreslerini içeren liste.
    """
    try:
        # Hedef IP'den olası % interface ifadesi temizlenir
        target_ip_clean = target_ip.split('%')[0]

        # Hedef IP için solicited-node multicast IP ve MAC hesaplanır
        multicast_ip, multicast_mac = solicited_node_multicast(target_ip_clean)

        # Layer 2 Ethernet başlığı (destination multicast MAC, source MAC)
        ether = Ether(dst=multicast_mac, src=src_mac)
        # Layer 3 IPv6 başlığı (source IP, destination solicited-node multicast IP)
        ipv6 = IPv6(src=src_ip, dst=multicast_ip)
        # ICMPv6 Neighbor Solicitation paketi, hedef IP adresi sorgulanır
        ns = ICMPv6ND_NS(tgt=target_ip)
        # Kaynak link-local MAC adresi opt olarak eklenir (ICMPv6 ND option)
        opt = ICMPv6NDOptSrcLLAddr(lladdr=src_mac)

        # Tüm paket katmanları üst üste bindirilir
        packet = ether / ipv6 / ns / opt

        # Paketi gönderir, cevapları bekler (srp = layer 2 send/receive)
        ans, _ = srp(packet, iface=interface, timeout=timeout, verbose=0)

        # Gelen cevaplardan Neighbor Advertisement (NA) içerenleri filtrele,
        # ve IP ve MAC bilgilerini liste olarak döndür
        return [
            {"ip": rcv[IPv6].src, "mac": rcv[Ether].src}
            for _, rcv in ans
            if rcv.haslayer(ICMPv6ND_NA)
        ]
    except Exception as e:
        print(f"ND hata ({target_ip}): {e}")
    return []


def ipv6_nd_scan_range(interface: str, network: str, src_ip: str, max_threads=100, max_hosts=1024) -> list[dict]:
    """
    Verilen IPv6 ağında belirlenen sayıda host için ND taraması yapar.

    Args:
        interface (str): Ağ arayüzü adı.
        network (str): Taranacak IPv6 ağı (CIDR formatında).
        src_ip (str): Kaynak IPv6 adresi (genellikle link-local).
        max_threads (int): Aynı anda açılacak maksimum thread sayısı.
        max_hosts (int): Taranacak maksimum host sayısı.

    Returns:
        list[dict]: Bulunan cihazların IP ve MAC adreslerinden oluşan liste.
    """
    try:
        # Girilen network parametresini IPv6Network nesnesine dönüştürür
        net = ipaddress.IPv6Network(network, strict=False)
    except ValueError as e:
        print(f"Geçersiz ağ: {e}")
        return []

    # Kaynak MAC adresini arayüzden alır
    src_mac = get_if_hwaddr(interface)
    # Ağdaki host IP adreslerini alır (max_hosts ile sınırlandırılır)
    targets = list(islice(net.hosts(), max_hosts))
    print(f"{len(targets)} adres taranıyor ({network})...")

    results = []
    # Çoklu iş parçacığı ile paralel tarama yapabilmek için ThreadPoolExecutor kullanılır
    with ThreadPoolExecutor(max_threads) as executor:
        # Her hedef IP için ipv6_nd_scan_single fonksiyonu ayrı thread'de çağrılır
        futures = {
            executor.submit(ipv6_nd_scan_single, interface, str(ip), src_ip, src_mac): ip
            for ip in targets
        }
        # İşler tamamlandıkça sonuçları toplar
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.extend(result)
    return results


def main():
   

    # Kullanıcıdan ağ arayüzü seçmesini ister
    iface = user_select_interface()
    # Seçilen arayüzün IP ve MAC adres bilgilerini alır
    addrs = get_interface_addresses(iface)
    # IPv6 adreslerini listeler
    ipv6_list = addrs.get("ipv6", [])

    # Kaynak IP adresimizi belirlemek için link-local IPv6 arar
    src_ip = None
    for addr_info in ipv6_list:
        ip_candidate = addr_info.get("address", "")
        try:
            # Link-local IPv6 adresi (fe80::/10) bulursa kaydeder ve döngüyü kırar
            if ipaddress.IPv6Address(ip_candidate.split('%')[0]).is_link_local:
                src_ip = ip_candidate
                break
        except Exception:
            continue

    # Eğer link-local IP bulunamadıysa programı sonlandırır
    if not src_ip:
        print(f"Seçilen arayüzde link-local IPv6 adresi bulunamadı.")
        exit(1)

    # Kullanıcıdan taranacak IPv6 ağı istenir, yoksa varsayılan fe80::/64 (link-local subnet) kullanılır
    network = input("Taranacak IPv6 ağı (default: fe80::/64): ").strip() or "fe80::/64"

    print(f"\nSeçilen arayüz: {iface}")
    print(f"Kaynak link-local IPv6: {src_ip}")
    print(f"Taranacak IPv6 ağı: {network}")

    # IPv6 ND taraması başlatılır
    found_devices = ipv6_nd_scan_range(iface, network, src_ip)

    # Bulunan cihazlar listelenir, yoksa uyarı verilir
    if found_devices:
        print("\nCihazlar bulundu:")
        seen = set()
        for d in found_devices:
            key = (d['ip'], d['mac'])
            if key not in seen:
                print(f"IP: {d['ip']:<40} MAC: {d['mac']}")
                seen.add(key)
    else:
        print("Hiçbir cihazdan yanıt alınamadı.")


if __name__ == "__main__":
    main()
