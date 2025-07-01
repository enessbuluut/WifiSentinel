from scapy.all import IP, IPv6, TCP, sr1, send
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(ip, port, timeout=1.5):
    if ':' in ip:
        pkt = IPv6(dst=ip)/TCP(dport=port, flags='S')
    else:
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')

    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return (port, "Filtered/No response")
    elif resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            # RST göndererek bağlantıyı kapat
            if ':' in ip:
                rst_pkt = IPv6(dst=ip)/TCP(dport=port, flags='R')
            else:
                rst_pkt = IP(dst=ip)/TCP(dport=port, flags='R')
            send(rst_pkt, verbose=0)
            return (port, "Open")
        elif resp[TCP].flags == 0x14:  # RST-ACK
            return (port, "Closed")
    return (port, "Unknown")

def scan_port_block(ip, start_port, end_port, max_workers=100):
    open_ports = []
    filtered_ports = []
    print(f"\n{ip} için TCP SYN port taraması başlıyor ({start_port}-{end_port})...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port+1)}
        for future in as_completed(futures):
            port, status = future.result()
            if status == "Open":
                print(f"Port {port}: Open")
                open_ports.append(port)
            elif status == "Filtered/No response":
                filtered_ports.append(port)

    print(f"{start_port}-{end_port} aralığında tarama tamamlandı. Açık portlar: {len(open_ports)}, Filtered/No response: {len(filtered_ports)}")
    return open_ports

def main():
    ip = input("Hedef IP (IPv4 veya IPv6): ").strip()
    start_port = input("Başlangıç portu (default 1): ").strip()
    end_port = input("Bitiş portu (default 65535): ").strip()

    start_port = int(start_port) if start_port.isdigit() else 1
    end_port = int(end_port) if end_port.isdigit() else 65535

    all_open_ports = []

    # Port aralığını 1024'erlik bloklara böl
    block_size = 1024
    for block_start in range(start_port, end_port + 1, block_size):
        block_end = min(block_start + block_size - 1, end_port)
        open_ports = scan_port_block(ip, block_start, block_end)
        all_open_ports.extend(open_ports)

    # Tüm açık portları göster
    all_open_ports.sort()
    print("\n--- Tüm açık portlar ---")
    if all_open_ports:
        for port in all_open_ports:
            print(f"Port {port}: Open")
    else:
        print("Hiç açık port bulunamadı.")

if __name__ == "__main__":
    main()
