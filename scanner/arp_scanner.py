from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from interface.interface_utils import get_interface_addresses, user_select_interface

def ag_tara(ip_araligi: str, tur_sayisi: int) -> list[dict]:
    """
    ARP taraması gerçekleştirir ve belirtilen IP aralığında aktif cihazları tespit eder.

    Parametreler:
        ip_araligi (str): CIDR formatında (örneğin, '192.168.1.0/24') hedef ağ aralığı.
        tur_sayisi (int): Taranacak tur sayısı, her turda ARP sorgusu gönderilir.

    İşleyiş:
        - Layer 2 (Ethernet) seviyesinde broadcast paketi oluşturulur.
        - Paket içerisinde ARP sorgusu ile hedef IP aralığı belirtilir.
        - scapy'nin srp fonksiyonu kullanılarak paketler gönderilir ve cevaplar toplanır.
        - Gelen cevaplarda her cihazın MAC ve IP adresi alınır.
        - Aynı MAC adresinden birden fazla cevap gelse bile tekil olarak tutulur.
        - Taranan cihazların bilgileri sözlük listesi olarak döndürülür.

    Neden tur_sayisi?
        Ağda anlık cihazların cevap vermeme ihtimali vardır,
        birden fazla deneme ile tespit doğruluğu artırılır.

    Dönüş:
        List[dict]: Her dict cihazın "mac" ve "ip" bilgilerini içerir.
    """
    print(f"ARP taraması başlatıldı: {ip_araligi}")

    # Broadcast MAC adresi hedef alınır (tüm ağ cihazlarına gönderilir)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # ARP sorgusu hedef IP aralığı için hazırlanır
    arp = ARP(pdst=str(ip_araligi))

    # Ethernet ve ARP paketleri birleştirilir
    packet = ether / arp

    # Bulunan cihazları saklamak için boş sözlük
    cihazlar = {}

    # Belirtilen tur sayısı kadar tarama yapılır
    for _ in range(tur_sayisi):
        # Katman 2 seviyesinde paket gönderme ve cevapları alma
        cevaplar = srp(packet, timeout=2, verbose=0)[0]

        # Gelen her cevap için
        for gönderilen, alınan in cevaplar:
            ip = alınan.psrc  # Kaynak IP adresi
            mac = alınan.hwsrc  # Kaynak MAC adresi

            # MAC adresi benzersiz anahtar olarak kullanılır
            cihazlar[mac] = ip

    print(f"{len(cihazlar)} cihaz bulundu.")

    # Cihazlar liste formatında döndürülür
    return [{"mac": mac, "ip": ip} for mac, ip in cihazlar.items()]

def main():
    """
    Kullanıcıdan ağ arayüzü seçimi alır,
    seçilen arayüzün IPv4 adreslerini öğrenir,
    ve her IPv4 CIDR aralığı için ARP taraması yapar.

    - Eğer arayüz seçilmezse veya IPv4 adresi yoksa işlem iptal edilir.
    - Tespit edilen cihazların IP ve MAC adresleri konsola yazdırılır.
    """
    # Kullanıcının ağ arayüzü seçmesi sağlanır
    iface_name = user_select_interface()
    if not iface_name:
        return

    # Seçilen arayüzün adres bilgileri alınır
    addrs = get_interface_addresses(iface_name)
    ipv4_list = addrs['ipv4']

    # Eğer arayüzde IPv4 adresi yoksa uyarı verilir
    if not ipv4_list:
        print("Seçilen arayüzde IPv4 adresi bulunamadı!")
        return

    # Her IPv4 adresi için ARP taraması yapılır
    for ipv4_eleman in ipv4_list:
        cihazlar = ag_tara(ipv4_eleman['cidr'], 3)
        if not cihazlar:
            continue
        else:
            print("Ağdaki cihazlar:")
            for cihaz in cihazlar:
                print(f"Cihaza ait IP bilgisi: {cihaz['ip']}, MAC adresi: {cihaz['mac']}")

if __name__ == "__main__":
    main()
