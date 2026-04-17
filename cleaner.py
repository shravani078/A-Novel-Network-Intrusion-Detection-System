"""
cleaner.py
==========
Clean, encode, scale and split the dataset.
"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import joblib
from pathlib import Path

DROP_COLUMNS = ["Flow ID", "Source IP", "Destination IP",
                "Source Port", "Destination Port", "Timestamp",
                "Fwd Header Length.1"]

def clean(df):
    print("🧹 Cleaning ...")
    df = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns], errors="ignore")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(inplace=True)
    print(f"   Dropped {before - len(df):,} rows with NaN/Inf")
    feat_cols = [c for c in df.columns if c != "Label"]
    const = [c for c in feat_cols if df[c].nunique() <= 1]
    df.drop(columns=const, inplace=True)
    print(f"   Dropped {len(const)} constant columns | Remaining features: {df.shape[1] - 1}")
    return df

def encode_labels(df, save_dir="data/processed/"):
    Path(save_dir).mkdir(parents=True, exist_ok=True)
    le = LabelEncoder()
    df = df.copy()
    df["Label"] = le.fit_transform(df["Label"])
    joblib.dump(le, f"{save_dir}/label_encoder.pkl")
    print("\n🏷️  Labels encoded:")
    for i, cls in enumerate(le.classes_):
        count = (df["Label"] == i).sum()
        print(f"   {i} → {cls}  ({count} samples)")
    return df, le

def scale_features(X_train, X_val, X_test, save_dir="data/processed/"):
    Path(save_dir).mkdir(parents=True, exist_ok=True)
    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_val   = scaler.transform(X_val)
    X_test  = scaler.transform(X_test)
    joblib.dump(scaler, f"{save_dir}/scaler.pkl")
    print("✅ Features scaled (MinMaxScaler saved)")
    return X_train, X_val, X_test

def split_data(df, test_size=0.15, val_size=0.15, random_state=42):
    """
    Split data into train/val/test.
    Automatically removes classes with too few samples to allow stratified splitting.
    """
    feat_cols = [c for c in df.columns if c != "Label"]
    X = df[feat_cols].values.astype(np.float32)
    y = df["Label"].values

    # ── Fix: remove classes with fewer than 3 samples ─────────────────────────
    from collections import Counter
    counts = Counter(y)
    min_samples_needed = 3   # need at least 1 in each split
    rare_classes = [cls for cls, cnt in counts.items() if cnt < min_samples_needed]

    if rare_classes:
        print(f"\n⚠️  Removing {len(rare_classes)} rare class(es) with < {min_samples_needed} samples: {rare_classes}")
        mask = np.isin(y, rare_classes, invert=True)
        X = X[mask]
        y = y[mask]
        print(f"   Remaining samples: {len(y):,}")

    # ── First split: train+val vs test ─────────────────────────────────────────
    try:
        X_tmp, X_test, y_tmp, y_test = train_test_split(
            X, y, test_size=test_size,
            random_state=random_state, stratify=y)
    except ValueError:
        # fallback: no stratify if still failing
        print("⚠️  Stratify failed — splitting without stratification")
        X_tmp, X_test, y_tmp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state)

    # ── Second split: train vs val ─────────────────────────────────────────────
    rel_val = val_size / (1.0 - test_size)
    try:
        X_train, X_val, y_train, y_val = train_test_split(
            X_tmp, y_tmp, test_size=rel_val,
            random_state=random_state, stratify=y_tmp)
    except ValueError:
        print("⚠️  Stratify failed for val split — splitting without stratification")
        X_train, X_val, y_train, y_val = train_test_split(
            X_tmp, y_tmp, test_size=rel_val, random_state=random_state)

    print(f"\n✂️  Split → Train:{len(X_train):,} | Val:{len(X_val):,} | Test:{len(X_test):,}")
    return X_train, X_val, X_test, y_train, y_val, y_test, feat_cols

def save_splits(X_train, X_val, X_test, y_train, y_val, y_test,
                save_dir="data/processed/"):
    Path(save_dir).mkdir(parents=True, exist_ok=True)
    for name, arr in [("X_train", X_train), ("X_val", X_val), ("X_test", X_test),
                      ("y_train", y_train), ("y_val", y_val), ("y_test", y_test)]:
        np.save(f"{save_dir}/{name}.npy", arr)
    print(f"💾 All splits saved to {save_dir}")

def load_splits(save_dir="data/processed/"):
    return (np.load(f"{save_dir}/X_train.npy"),
            np.load(f"{save_dir}/X_val.npy"),
            np.load(f"{save_dir}/X_test.npy"),
            np.load(f"{save_dir}/y_train.npy"),
            np.load(f"{save_dir}/y_val.npy"),
            np.load(f"{save_dir}/y_test.npy"))