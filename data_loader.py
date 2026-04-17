"""
data_loader.py
--------------
Loads and merges all CICIDS-2017 CSV files from the data/raw/ directory.
Handles column name normalization and basic sanity checks.
"""

import os
import pandas as pd
import numpy as np
from pathlib import Path


# ── Label mapping: group all CICIDS-2017 attack names ────────────────────────
LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Bot": "Bot",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Infiltration": "Infiltration",
    "Web Attack – Sql Injection": "Web Attack",
    "Heartbleed": "Heartbleed",
}


def load_cicids2017(data_dir: str = "data/raw/", sample_frac: float = 1.0) -> pd.DataFrame:
    """
    Load all CICIDS-2017 CSV files from data_dir and return a single DataFrame.

    Parameters
    ----------
    data_dir   : path to directory containing raw CSV files
    sample_frac: fraction of each file to load (use 0.1 for quick testing)

    Returns
    -------
    pd.DataFrame with normalized column names and a 'Label' column
    """
    data_path = Path(data_dir)
    csv_files = sorted(data_path.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in '{data_dir}'.\n"
            "Please download CICIDS-2017 from:\n"
            "  https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "and place the CSV files in data/raw/"
        )

    dfs = []
    for f in csv_files:
        print(f"  Loading {f.name} …")
        df = pd.read_csv(f, low_memory=False)
        if sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=42)
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    combined = _normalize_columns(combined)
    print(f"\n✅ Total records loaded : {len(combined):,}")
    print(f"   Columns              : {combined.shape[1]}")
    return combined


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names and unify label column."""
    df.columns = df.columns.str.strip()

    # Rename label column to standard 'Label'
    for col in df.columns:
        if col.lower() == "label":
            df.rename(columns={col: "Label"}, inplace=True)
            break

    # Normalize label values
    df["Label"] = df["Label"].str.strip()
    df["Label"] = df["Label"].replace(LABEL_MAP)

    return df


def show_class_distribution(df: pd.DataFrame) -> None:
    """Print class distribution of the Label column."""
    counts = df["Label"].value_counts()
    total = len(df)
    print("\n📊 Class Distribution:")
    print("-" * 45)
    for label, count in counts.items():
        pct = 100.0 * count / total
        print(f"  {label:<25} {count:>8,}  ({pct:5.2f}%)")
    print("-" * 45)
    print(f"  {'TOTAL':<25} {total:>8,}")


if __name__ == "__main__":
    df = load_cicids2017(sample_frac=0.05)   # quick sanity check
    show_class_distribution(df)
