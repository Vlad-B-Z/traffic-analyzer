#!/usr/bin/env python3
"""
Traffic Analyzer — мінімальний інструмент для:
1) перехоплення пакетів "наживо" АБО читання з .pcap файлу,
2) підрахунку базової статистики (топ IP, порти, протоколи),
3) збереження результатів у CSV + текстовий summary.

⚠️ Live-sniff зазвичай потребує sudo або capability на python:
   sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))

Приклади запуску:
- live:  sudo python3 main.py --iface eth0 --duration 30
- pcap:  python3 main.py --pcap samples/example.pcap
"""

import argparse
from collections import Counter
from pathlib import Path

import pandas as pd
from scapy.all import sniff, rdpcap, IP, TCP, UDP


def parse_args():
    p = argparse.ArgumentParser(description="Simple Network Traffic Analyzer")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="Інтерфейс для перехоплення (потрібен sudo)")
    src.add_argument("--pcap", help="Шлях до .pcap файлу")
    p.add_argument("--duration", type=int, default=20, help="Секунд перехоплення (live)")
    p.add_argument("--outdir", default="out", help="Куди скласти звіти/CSV")
    return p.parse_args()


def analyze_packets(packets):
    stats = {
        "total": 0,
        "by_proto": Counter(),
        "by_sport": Counter(),
        "by_dport": Counter(),
        "by_src": Counter(),
        "by_dst": Counter(),
    }
    rows = []
    for pkt in packets:
        stats["total"] += 1
        proto = "OTHER"
        src = dst = None
        sport = dport = None

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        stats["by_proto"][proto] += 1
        if sport: stats["by_sport"][sport] += 1
        if dport: stats["by_dport"][dport] += 1
        if src: stats["by_src"][src] += 1
        if dst: stats["by_dst"][dst] += 1

        rows.append({"proto": proto, "src": src, "dst": dst, "sport": sport, "dport": dport})

    df = pd.DataFrame(rows)
    return stats, df


def save_reports(stats, df, outdir):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    df.to_csv(f"{outdir}/packets.csv", index=False)

    def top_to_df(counter, colname):
        return pd.DataFrame(counter.most_common(10), columns=[colname, "count"])

    top_proto = top_to_df(stats["by_proto"], "proto")
    top_src   = top_to_df(stats["by_src"], "src")
    top_dst   = top_to_df(stats["by_dst"], "dst")
    top_sport = top_to_df(stats["by_sport"], "sport")
    top_dport = top_to_df(stats["by_dport"], "dport")

    top_proto.to_csv(f"{outdir}/top_proto.csv", index=False)
    top_src.to_csv(f"{outdir}/top_src.csv", index=False)
    top_dst.to_csv(f"{outdir}/top_dst.csv", index=False)
    top_sport.to_csv(f"{outdir}/top_sport.csv", index=False)
    top_dport.to_csv(f"{outdir}/top_dport.csv", index=False)

    with open(f"{outdir}/summary.txt", "w") as f:
        f.write(f"Total packets: {stats['total']}\n")
        f.write(f"By protocol: {stats['by_proto']}\n")
        f.write(f"Top src IPs: {stats['by_src'].most_common(5)}\n")
        f.write(f"Top dst IPs: {stats['by_dst'].most_common(5)}\n")
        f.write(f"Top src ports: {stats['by_sport'].most_common(5)}\n")
        f.write(f"Top dst ports: {stats['by_dport'].most_common(5)}\n")


def main():
    args = parse_args()
    if args.pcap:
        packets = rdpcap(args.pcap)
    else:
        packets = sniff(iface=args.iface, timeout=args.duration)
    stats, df = analyze_packets(packets)
    save_reports(stats, df, args.outdir)
    print(f"[OK] Saved CSV & reports to {args.outdir}/")


if __name__ == "__main__":
    main()
