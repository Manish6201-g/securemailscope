import os
import struct

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)

def write_pcap(filepath: str, packets: list):
    with open(filepath, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_usec, pkt_bytes in packets:
            incl_len = len(pkt_bytes)
            orig_len = incl_len
            f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            f.write(pkt_bytes)

def make_eth_ip_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00"
    ip_src_b = bytes(map(int, src_ip.split(".")))
    ip_dst_b = bytes(map(int, dst_ip.split(".")))
    total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 54321, 0x4000, 64, 6, 0, ip_src_b, ip_dst_b)
    data_offset = (5 << 4)
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset, flags, 65535, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload

def create_sample_pcaps():
    vuln_path = os.path.join(DATA_DIR, "sample_vulnerable.pcap")
    remed_path = os.path.join(DATA_DIR, "sample_remediated.pcap")

    c_ip, s_ip = "192.168.1.105", "192.168.1.10"
    c_port, s_port = 54321, 25

    pkts = []
    pkts.append((1700000000, 100, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1000, 0, 0x02)))
    pkts.append((1700000000, 200, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 2000, 1001, 0x12)))
    pkts.append((1700000000, 300, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1001, 2001, 0x10)))
    pkts.append((1700000000, 400, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 2001, 1001, 0x18, b"220 mail.college.example ESMTP Postfix\r\n")))
    pkts.append((1700000000, 500, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1001, 2040, 0x18, b"EHLO client.college.example\r\n")))
    pkts.append((1700000000, 600, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 2040, 1030, 0x18, b"250-mail.college.example\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")))
    pkts.append((1700000000, 700, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1030, 2110, 0x18, b"STARTTLS\r\n")))
    pkts.append((1700000000, 800, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 2110, 1040, 0x18, b"220 2.0.0 Ready to start TLS\r\n")))

    sh_payload = (
        b"\x16" +
        b"\x03\x01" +
        b"\x00\x2e" +
        b"\x02" +
        b"\x00\x00\x2a" +
        b"\x03\x01" +
        b"\x11" * 32 +
        b"\x00" +
        b"\x00\x0a" +
        b"\x00"
    )
    pkts.append((1700000000, 900, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 2140, 1040, 0x18, sh_payload)))
    write_pcap(vuln_path, pkts)

    remed_pkts = []
    c_port = 54322
    remed_pkts.append((1700000100, 100, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 3000, 0, 0x02)))
    remed_pkts.append((1700000100, 200, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 4000, 3001, 0x12)))
    remed_pkts.append((1700000100, 300, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 3001, 4001, 0x10)))
    remed_pkts.append((1700000100, 400, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 4001, 3001, 0x18, b"220 mail.college.example ESMTP Postfix (Hardened)\r\n")))
    remed_pkts.append((1700000100, 500, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 3001, 4050, 0x18, b"EHLO client.college.example\r\n")))
    remed_pkts.append((1700000100, 600, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 4050, 3030, 0x18, b"250-mail.college.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n")))
    remed_pkts.append((1700000100, 700, make_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 3030, 4110, 0x18, b"STARTTLS\r\n")))
    remed_pkts.append((1700000100, 800, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 4110, 3040, 0x18, b"220 2.0.0 Ready to start TLS\r\n")))

    sh_remed = (
        b"\x16" +
        b"\x03\x03" +
        b"\x00\x2e" +
        b"\x02" +
        b"\x00\x00\x2a" +
        b"\x03\x03" +
        b"\x22" * 32 +
        b"\x00" +
        b"\xc0\x2f" +
        b"\x00"
    )
    remed_pkts.append((1700000100, 900, make_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 4140, 3040, 0x18, sh_remed)))
    write_pcap(remed_path, remed_pkts)

    return vuln_path, remed_path

if __name__ == "__main__":
    v, r = create_sample_pcaps()
    print(f"Generated clean PCAPs: {v}, {r}")
