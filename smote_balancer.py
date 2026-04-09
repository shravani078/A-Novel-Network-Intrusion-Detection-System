"""
smote_balancer.py
=================
Fast class balancing using Random Oversampling.
Much faster than SMOTE — works well for large datasets.
"""
import numpy as np
from collections import Counter


def apply_smote(X_train, y_train, random_state=42):
    """
    Fast balancing using Random Oversampling (much faster than SMOTE).
    Duplicates minority class samples randomly instead of generating synthetic ones.
    """
    print("\n⚖️  Balancing classes with Random Oversampling (fast mode) ...")
    print(f"   Before — total: {len(y_train):,}")

    counts = Counter(y_train)
    for cls, cnt in sorted(counts.items()):
        print(f"     Class {cls}: {cnt:>8,}  ({100*cnt/len(y_train):.2f}%)")

    # Find the majority class count
    max_count = max(counts.values())

    X_list = [X_train]
    y_list = [y_train]

    np.random.seed(random_state)

    for cls, cnt in counts.items():
        if cnt < max_count:
            shortage   = max_count - cnt
            cls_mask   = (y_train == cls)
            X_cls      = X_train[cls_mask]
            y_cls      = y_train[cls_mask]
            # randomly pick samples to duplicate
            idx        = np.random.choice(len(X_cls), size=shortage, replace=True)
            X_list.append(X_cls[idx])
            y_list.append(y_cls[idx])

    X_res = np.vstack(X_list)
    y_res = np.concatenate(y_list)

    # Shuffle
    perm  = np.random.permutation(len(X_res))
    X_res = X_res[perm]
    y_res = y_res[perm]

    print(f"\n   After  — total: {len(y_res):,}")
    counts_after = Counter(y_res)
    for cls, cnt in sorted(counts_after.items()):
        print(f"     Class {cls}: {cnt:>8,}  ({100*cnt/len(y_res):.2f}%)")

    return X_res, y_res