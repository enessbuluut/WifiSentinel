import ipaddress
from scapy.all import sr1, IP, ICMP, IPv6, ICMPv6EchoRequest


def is_valid_ip(ip_str):
    """
    Verilen IP adresi string'inin geçerli IPv4 veya IPv6 adresi olup olmadığını kontrol eder.

    Args:
        ip_str (str): Kontrol edilecek IP adresi string'i.

    Returns:
        ipaddress.IPv4Address veya ipaddress.IPv6Address objesi: Eğer geçerliyse,
        None: Geçerli değilse.

    Açıklama:
        - ipaddress.ip_address fonksiyonu, verilen string'i IP adres objesine çevirir.
        - Eğer string geçerli bir IP değilse, ValueError fırlatır.
        - Burada try-except bloğuyla bu hata yakalanır ve None döndürülür.
    """
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def single_ping(ip_str):
    """
    Verilen IP adresine ICMP Echo Request (ping) paketi gönderir ve yanıt alır.

    Args:
        ip_str (str): Ping atılacak IP adresi.

    İşleyiş:
        1. Öncelikle IP adresinin geçerli olup olmadığı kontrol edilir.
           Geçerli değilse fonksiyon sonlandırılır.
        2. IP sürümü tespit edilir (IPv4 veya IPv6).
        3. Scapy kullanılarak uygun ICMP paketi oluşturulur:
            - IPv4 için IP/ICMP paketi,
            - IPv6 için IPv6/ICMPv6 Echo Request paketi.
        4. sr1() fonksiyonu ile tek bir paket gönderilir ve yanıt beklenir.
        5. Yanıt varsa, paket detayları gösterilir.
           Yoksa, "Yanıt alınamadı" mesajı verilir.
    """
    ip_obj = is_valid_ip(ip_str)
    if not ip_obj:
        print("Geçersiz IP adresi.")
        return

    print(f"\n{ip_str} adresine ICMP ping gönderiliyor...\n")

    # IP sürümüne göre paket oluşturma:
    # IPv4 için standart ICMP Echo Request
    if ip_obj.version == 4:
        pkt = IP(dst=ip_str) / ICMP()
    # IPv6 için ICMPv6 Echo Request kullanılır
    elif ip_obj.version == 6:
        pkt = IPv6(dst=ip_str) / ICMPv6EchoRequest()
    else:
        # Genellikle buraya ulaşılmaz ama ekstra kontrol için
        print("Bilinmeyen IP sürümü.")
        return

    # sr1(): Scapy'de "send and receive one packet" anlamına gelir.
    # Belirtilen paketi gönderir ve ilk gelen cevabı bekler.
    # timeout ile bekleme süresi 2 saniye olarak ayarlanır.
    # verbose=0 ile Scapy konsola işlem detaylarını yazmaz.
    response = sr1(pkt, timeout=2, verbose=0)

    if response:
        print("Yanıt geldi!")
        print("-" * 50)
        # Yanıt paketi detaylarını gösterir (katman katman, alanlar vs.)
        response.show()
        print("-" * 50)
    else:
        # 2 saniye içinde cevap gelmediyse buraya düşer
        print("Yanıt alınamadı.")


if __name__ == "__main__":
    # Kullanıcıdan ping atılacak IP adresini alıyoruz.
    hedef_ip = input("Ping atmak istediğiniz IP adresini girin: ").strip()
    # Girilen IP ile ping işlemini başlatıyoruz
    single_ping(hedef_ip)
