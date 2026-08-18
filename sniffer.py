import socket
import struct
import sys
from typing import Optional, Tuple


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

def format_mac(bytes_addr: bytes) -> str:
    
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

def format_ipv4(bytes_addr: bytes) -> str:
    
    return '.'.join(map(str, bytes_addr))

def unpack_ethernet_frame(data: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    
    if len(data) < 14:
        return None
    
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dest_mac), format_mac(src_mac), eth_proto, data[14:]

def unpack_ipv4_packet(data: bytes) -> Optional[Tuple[int, int, str, str, bytes]]:
   
   
    if len(data) < 20:
        return None

    version_header_length = data[0]
    ihl = version_header_length & 0x0F
    header_length = ihl * 4

    if header_length < 20 or len(data) < header_length:
        return None

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

def parse_tcp_flags(flags_byte: int) -> str:
    
    flag_names = []
    if flags_byte & 0x20: flag_names.append("URG")
    if flags_byte & 0x10: flag_names.append("ACK")
    if flags_byte & 0x08: flag_names.append("PSH")
    if flags_byte & 0x04: flag_names.append("RST")
    if flags_byte & 0x02: flag_names.append("SYN")
    if flags_byte & 0x01: flag_names.append("FIN")
    return ', '.join(flag_names) if flag_names else "NONE"

def unpack_tcp_segment(data: bytes) -> Optional[Tuple[int, int, int, int, str, bytes]]:
    
    
    if len(data) < 20:
        return None

    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    
    data_offset = (offset_reserved_flags >> 12) * 4
    if data_offset < 20 or len(data) < data_offset:
        return None

    flags = offset_reserved_flags & 0x3F
    flags_str = parse_tcp_flags(flags)

    return src_port, dest_port, seq, ack, flags_str, data[data_offset:]

def unpack_udp_segment(data: bytes) -> Optional[Tuple[int, int, int, bytes]]:
    
    if len(data) < 8:
        return None

    src_port, dest_port, length = struct.unpack('! H H H 2x', data[:8])
    return src_port, dest_port, length, data[8:]

def main() -> None:
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[-] Hata: Raw socket çalıştırmak için root yetkisi (sudo) gereklidir.")
        sys.exit(1)
    except AttributeError:
        print("[-] Hata: socket.AF_PACKET yalnızca Linux ortamında desteklenir.")
        sys.exit(1)

    print("[*] Ağ analiz aracı dinlemede... (Durdurmak için CTRL+C)\n" + "=" * 60)

    try:
        while True:
            try:
                raw_data, _ = raw_socket.recvfrom(65535)
                eth_result = unpack_ethernet_frame(raw_data)
                if not eth_result:
                    continue

                dest_mac, src_mac, eth_proto, ip_data = eth_result

                
                if eth_proto == ETHERTYPE_IPV4:
                    ip_result = unpack_ipv4_packet(ip_data)
                    if not ip_result:
                        continue

                    ttl, proto, src_ip, dest_ip, transport_data = ip_result

                    
                    if proto == 6:
                        tcp_result = unpack_tcp_segment(transport_data)
                        if tcp_result:
                            src_port, dest_port, seq, ack, flags, payload = tcp_result
                            print(f"[TCP] {src_ip}:{src_port} -> {dest_ip}:{dest_port} | TTL: {ttl} | Flags: [{flags}]")
                            print(f"      Seq: {seq} | Ack: {ack} | MAC: {src_mac} -> {dest_mac}")
                            if payload:
                                print(f"      Payload ({len(payload)}B): {payload[:40]!r}")
                            print("-" * 60)

                    elif proto == 17:
                        udp_result = unpack_udp_segment(transport_data)
                        if udp_result:
                            src_port, dest_port, length, payload = udp_result
                            print(f"[UDP] {src_ip}:{src_port} -> {dest_ip}:{dest_port} | TTL: {ttl} | Len: {length}")
                            print(f"      MAC: {src_mac} -> {dest_mac}")
                            if payload:
                                print(f"      Payload ({len(payload)}B): {payload[:40]!r}")
                            print("-" * 60)

                    elif proto == 1:
                        if len(transport_data) >= 4:
                            icmp_type, code = struct.unpack('! B B', transport_data[:2])
                            print(f"[ICMP] {src_ip} -> {dest_ip} | TTL: {ttl} | Tip: {icmp_type}, Kod: {code}")
                            print("-" * 60)

                elif eth_proto == ETHERTYPE_ARP:
                    print(f"[ARP]  EtherType: 0x{eth_proto:04X} | MAC: {src_mac} -> {dest_mac}")
                    print("-" * 60)

            except struct.error:
                continue

    except KeyboardInterrupt:
        print("\n[*] Dinleme sonlandırıldı.")
        raw_socket.close()

if __name__ == "__main__":
    main()