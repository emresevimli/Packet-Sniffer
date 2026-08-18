# Lightweight Python Raw Socket Packet Sniffer

Linux ortamında `AF_PACKET` ve `SOCK_RAW` kullanarak Ethernet, IPv4, TCP, UDP, ICMP ve ARP paketlerini harici bağımlılık olmadan ayrıştıran hafif bir ağ analiz aracı.

## Özellikler

* **Katman 2 (Data Link):** Ethernet Frame ayrıştırma (MAC adresleri, EtherType).
* **Katman 3 (Network):** IPv4 başlığı, TTL, protokol tespiti; ARP tespiti.
* **Katman 4 (Transport):**
  * **TCP:** Portlar, Sequence/Ack numaraları, Bayraklar (SYN, ACK, FIN, RST, PSH, URG), Payload özeti.
  * **UDP:** Portlar, Paket uzunluğu, Payload özeti.
  * **ICMP:** Tip ve Kod çözümleme.
* **Sıfır Dış Bağımlılık:** Yalnızca Python standart kütüphanesi (`socket`, `struct`).

## Gereksinimler

* **İşletim Sistemi:** Linux (Raw socket ve `AF_PACKET` desteği için)
* **Python Sürümü:** Python 3.8+
* **Yetki:** Raw socket dinleyebilmek için `root` (sudo) yetkisi

## Kurulum ve Çalıştırma

```bash

cd py-packet-sniffer

# Root yetkisi ile çalıştırın
sudo python3 sniffer.py
```

