import ipaddress
import socket
import psutil

def get_all_interfaces() -> list:
    stats = psutil.net_if_stats()
    '''
psutil.net_if_stats() fonksiyonu ne yapıyor?
psutil Python’un sistem ve proses bilgisi alma modülü, cross-platform(Cross-platform olması demek: Windows, Linux, macOS gibi farklı 
işletim sistemlerinde aynı kodla çalışabilir ve sistem bilgilerini benzer şekilde toplayabilir) destek sağlar.

net_if_stats() her ağ arayüzü için istatistiksel bilgi döner.

Dönen veri tipik olarak { arayüz_ismi: snicstats(...), ... } şeklindedir.

İçindeki snicstats nesnesi şunları içerir:

 isup: Arayüz aktif mi? (True/False)
stat.isup → bu boolean, arayüzün aktif olup olmadığını gösteriyor.

 duplex: Duplex modu (tam-duplex, yarı-duplex gibi) — bağlantı türünü belirtir, örn: 2 = full duplex, 1 = half duplex, 0 = unknown
Duplex ağ iletişiminde, veri akışının yönünü belirler:

Half Duplex: Aynı anda sadece tek yönlü iletişim (walkie-talkie gibi)

Full Duplex: Aynı anda iki yönlü iletişim (telefon görüşmesi gibi)

 speed: Mbps cinsinden hız

 mtu: Maksimum taşıma birimi (paket boyutu) — genellikle 1500 civarı olur Ethernet için
'''
    interfaces = []
    for iface_name, stat in stats.items():
        interfaces.append({
            "name": iface_name,
            "is_up": stat.isup,
            "duplex": stat.duplex,
            "speed": stat.speed,
            "mtu": stat.mtu
        })
    return interfaces

def get_interface_addresses(interface_name: str) -> dict[str, list[dict]]:
    addrs = psutil.net_if_addrs().get(interface_name, [])
    '''
    psutil.net_if_addrs() fonksiyonu normalde tüm ağ arayüzlerinin adres bilgilerini döner.

    Dönen yapı: { arayüz_ismi: [adres_objeleri...], ... }
    
    Burada .get(interface_name, []) ile sadece seçilen arayüzün adres bilgileri çekiliyor. Eğer arayüz yoksa boş liste dönüyor.

Örneğin:
    [ snicaddr(family=AddressFamily.AF_INET, address='192.168.1.100', netmask='255.255.255.0', ...),
    snicaddr(family=AddressFamily.AF_PACKET, address='00:1a:2b:3c:4d:5e', netmask=None, ...),
    snicaddr(family=AddressFamily.AF_INET6, address='fe80::abcd:1234:5678:9abc', netmask='ffff:ffff:ffff:ffff::', ...) ]
Alan Adı	            Anlamı	                              Tip
family	    Adres türü (IPv4, IPv6, MAC, vs.)	        AddressFamily enum
address	    IP veya MAC adresi (                        string)	str
netmask	    Ağ maskesi (string veya None)	            str veya None
broadcast	Broadcast adresi (string veya None)         str veya None
ptp	        Point-to-Point adres (string veya None)	    str veya None

.... kısmında aşağıdakileri de dönebilir
    broadcast: Broadcast adresi (örn: 192.168.1.255), bazı arayüzlerde mevcut olabilir

    ptp: Point-to-point adresi, genellikle PPP veya VPN bağlantılarında görülür
'''

    ipv4_list, ipv6_list = [], []
    mac_address = []
    for addr in addrs:
        if addr.family == socket.AF_INET:
            try:
                network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                ipv4_list.append({
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "cidr": str(network)
                })
            except:
                pass
        elif addr.family == socket.AF_INET6:
            try:
                ip = addr.address.split('%')[0]
                prefix_len = 64
                if addr.netmask:
                    prefix_len = int(addr.netmask)
                network = ipaddress.IPv6Network(f"{ip}/{prefix_len}", strict=False)
                ipv6_list.append({
                    "address": ip,
                    "prefix_length": prefix_len,
                    "cidr": str(network)
                })
            except:
                pass
        elif addr.family==psutil.AF_LINK:
            mac_address.append({
                "mac":addr.address
            })
    return {"ipv4": ipv4_list, "ipv6": ipv6_list,"mac": mac_address}
'''
"""
Fonksiyon: get_interface_addresses(interface_name: str) -> dict[str, list[dict]]

Açıklama:
Bu fonksiyon, verilen ağ arayüzü adına (interface_name) karşılık gelen tüm IP ve MAC adres bilgilerini toplar ve düzenler.

Yapılan Değişiklikler ve Nedenleri:
- MAC adreslerini tekil string yerine, IPv4 ve IPv6 adresleri gibi, liste içerisinde sözlük yapısında tuttuk.
  Bunun sebebi:
    * Type hint standardına uyum sağlamak (tüm adres tipleri aynı veri yapısında listeler içinde sözlük olarak tutuluyor).
    * Kodun tutarlılığını artırmak, böylece veri işleme ve genişletme süreçleri kolaylaşıyor.
    * Bir ağ arayüzünün birden fazla MAC adresi olabileceği durumlara (sanal arayüzler, VPN, container vb.) hazır olmak.

- IP adreslerinin family türüne göre ayrılması:
    * IPv4 için socket.AF_INET
    * IPv6 için socket.AF_INET6
    * MAC adresleri için psutil.AF_LINK kullanıldı.
  Bu ayrım, platform bağımsız olarak doğru adres türlerini güvenilir şekilde almamızı sağlar.

- IPv6 adreslerinde '%' karakterinden sonraki interface ID kısmı çıkarıldı (ör: 'fe80::1%eth0' → 'fe80::1').
  Bu, adresin standart formatını sağlamak ve ağ işlemlerinde uyumluluk için önemlidir.

- IP adresleri ipaddress modülü kullanılarak Network nesnesine dönüştürüldü ve CIDR formatı hesaplandı.
  Bu sayede, adres ve subnet bilgisi doğrulanıp, standart formata dönüştürülüyor.

Platform Uyumluluğu:
- psutil kütüphanesi Windows, Linux ve MacOS dahil çoklu platformlarda ağ arayüzü bilgilerini sağlaması sebebiyle tercih edilmiştir.
- Socket ve psutil kombinasyonu ile farklı işletim sistemlerindeki adres türleri doğru ayrıştırılır.

Sonuç:
Bu yapı, profesyonel, genişletilebilir ve tutarlı bir adres bilgi modeli sunar.
Tüm adres tipleri liste içinde sözlük olarak tutulduğu için, ileride yapılacak analizlerde ve raporlamalarda kod karmaşası azalır.
"""'''

def detect_interface_type(interface_name: str) -> str:
    name_lower = interface_name.lower()
    if name_lower.startswith(("eth", "en", "ether")):
        return "Ethernet"
    elif name_lower.startswith(("wlan", "wi", "wl")):
        return "Wi-Fi"
    elif name_lower.startswith(("lo", "loopback")):
        return "Loopback"
    elif name_lower.startswith(("tun", "tap", "vpn", "ppp")):
        return "VPN"
    else:
        return "Other"

def user_select_interface() -> str:
    interfaces = get_all_interfaces()
    active_interfaces = [iface for iface in interfaces if iface["is_up"]]

    if not active_interfaces:
        print("Aktif ağ arayüzü bulunamadı!")
        return None

    print("Aktif ağ arayüzleri:")
    for idx, iface in enumerate(active_interfaces):
        itype = detect_interface_type(iface["name"])
        print(f"{idx + 1}. {iface['name']} ({itype})")

    while True:
        try:
            choice = int(input("Bir arayüz seçin (numara girin): "))
            if 1 <= choice <= len(active_interfaces):
                selected_iface = active_interfaces[choice - 1]
                print(f"Seçilen arayüz: {selected_iface['name']}")
                return selected_iface['name']
            else:
                print("Geçersiz seçim. Tekrar deneyin.")
        except ValueError:
            print("Lütfen sayı girin.")
