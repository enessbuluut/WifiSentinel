import ipaddress
import subprocess
from scanner.nd_scanner import ipv6_nd_scan_single
from interface.interface_utils import user_select_interface, get_interface_addresses


def get_interface_index(interface_name: str) -> int | None:
    """
    Windows için interface ismine karşılık gelen index değerini döner.
    netsh interface ipv6 show interfaces komutu ile elde edilir.
    """
    try:
        output = subprocess.check_output(
            ["netsh", "interface", "ipv6", "show", "interfaces"],
            text=True,
            encoding="utf-8"
        )
        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            # Format örneği:
            # Idx     Met         MTU          State                Name
            # ---     ---         ---          -----                ----
            # 6       50          1500         connected            Ethernet
            if line.endswith(interface_name):
                parts = line.split()
                if parts:
                    try:
                        idx = int(parts[0])
                        return idx
                    except:
                        pass
    except Exception as e:
        print(f"Interface index bulma hatası: {e}")
    return None


def normalize_mac(mac: str) -> str:
    """
    MAC adresini 'xx:xx:xx:xx:xx:xx' formatına çevirir.
    """
    return mac.lower().replace("-", ":")


def find_modem_link_local_ipv6(interface: str) -> str | None:
    """
    Windows'ta 'netsh interface ipv6 show neighbors' komutunu kullanarak
    belirtilen interface üzerinde modem/router link-local IPv6 adresini bulur.
    Router tipinde ve link-local IP olanları arar.
    """
    try:
        output = subprocess.check_output(
            ["netsh", "interface", "ipv6", "show", "neighbors"],
            text=True,
            encoding="utf-8"
        )
        lines = output.splitlines()

        current_iface = None
        target_interface = interface.lower()

        # Interface numarasını alalım
        idx = get_interface_index(interface)
        if idx is None:
            print("Interface index alınamadı, modem IP bulunamayabilir.")

        for line in lines:
            line = line.strip()
            if line.startswith("Interface "):
                # Interface 6: Ethernet
                parts = line.split(":")
                if len(parts) >= 2:
                    current_iface = parts[1].strip().lower()
                else:
                    current_iface = None
                continue

            # Eğer şu anda doğru interface bloğundaysak
            if current_iface == target_interface:
                # Satırdaki IP, MAC ve Type bilgisini almaya çalışalım
                # Satır formatı: IP (boşluk) MAC (boşluk) Type
                # Örnek: fe80::5e64:8eff:fe10:3190   5c-64-8e-10-31-90  Stale (Router)

                parts = line.split()
                if len(parts) < 3:
                    continue

                ip_part = parts[0]
                mac_part = parts[1]
                type_part = " ".join(parts[2:])

                # Link-local olmalı ve Router tipinde olmalı
                try:
                    ip_obj = ipaddress.IPv6Address(ip_part)
                    if ip_obj.is_link_local and ("router" in type_part.lower()):
                        if idx is not None:
                            return f"{ip_part}%{idx}"
                        else:
                            return ip_part
                except:
                    continue
    except Exception as e:
        print(f"Modem link-local IPv6 bulma hatası: {e}")
    return None


def main():
    iface = user_select_interface()
    if not iface:
        print("Arayüz seçilmedi, çıkılıyor.")
        return

    addrs = get_interface_addresses(iface)

    # Link-local IPv6 adresini al
    ipv6_list = addrs.get("ipv6", [])
    src_ip = None
    for addr_info in ipv6_list:
        ip_candidate = addr_info.get("address", "")
        try:
            if ipaddress.IPv6Address(ip_candidate).is_link_local:
                src_ip = ip_candidate
                break
        except:
            continue

    if not src_ip:
        print("Seçilen arayüzde link-local IPv6 adresi bulunamadı.")
        return

    # MAC adresini al ve normalize et
    mac_list = addrs.get("mac", [])
    src_mac = None
    if mac_list and isinstance(mac_list, list):
        first_mac_dict = mac_list[0]
        if isinstance(first_mac_dict, dict):
            raw_mac = first_mac_dict.get("mac")
            if raw_mac:
                src_mac = normalize_mac(raw_mac)

    if not src_mac:
        print("MAC adresi alınamadı, varsayılan MAC kullanılacak.")
        src_mac = "00:00:00:00:00:00"

    # Modem link-local IPv6 bul
    modem_ll_ipv6 = find_modem_link_local_ipv6(iface)
    if not modem_ll_ipv6:
        print("Modem link-local IPv6 bulunamadı.")
        return

    print(f"Modem link-local IPv6 bulundu: {modem_ll_ipv6}")
    print(f"Kullanılan kaynak IP: {src_ip}")

    print(f"Modeme ND sorgusu gönderiliyor: {modem_ll_ipv6}")
    results = ipv6_nd_scan_single(iface, modem_ll_ipv6, src_ip, src_mac, timeout=3)

    if results:
        for res in results:
            print(f"Yanıt alındı: IP: {res['ip']} MAC: {res['mac']}")
    else:
        print("Yanıt alınamadı.")


if __name__ == "__main__":
    main()
