#!/usr/bin/env python3
"""
Окремий скрипт для побудови одного простого графіка з packets.csv.

Запуск:
  python3 visualize.py out/packets.csv
"""
import argparse
import pandas as pd
import matplotlib.pyplot as plt

def parse_args():
    p = argparse.ArgumentParser(description="Plot simple charts from packets.csv")
    p.add_argument("csv", help="Шлях до out/packets.csv")
    return p.parse_args()

def main():
    args = parse_args()
    df = pd.read_csv(args.csv)
    ax = (
        df["dport"]
        .dropna()
        .astype(int)
        .value_counts()
        .head(10)
        .sort_values(ascending=True)
        .plot(kind="barh")
    )
    ax.set_xlabel("Кількість пакетів")
    ax.set_ylabel("Порт (dst)")
    ax.set_title("Top Destination Ports")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
