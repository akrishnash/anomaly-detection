# CIC-IDS2017 Network Anomaly Detection — Isolation Forest Metrics Report

This document reports the performance metrics of the **Isolation Forest** model on the **CIC-IDS2017** dataset, comparing the use of **all 77 features** vs. a subset of the **top 13 features**.

---

## Dataset Characteristics
*   **Total Dataset Size**: 56,661 network flows
*   **Normal Flows (BENIGN)**: 22,731
*   **Attack/Anomaly Flows (DoS, PortScan, etc.)**: 33,930
*   **Contamination Rate**: 49.0000%

---

## Feature Comparison
*   **All Features Config**: Using all **77 numerical features** present in the dataset.
*   **13 Features Config**: Using only the top 13 features most correlated with the attack labels:
    1. `Min Packet Length` (correlation: 0.4775)
    2. `Bwd Packet Length Min` (correlation: 0.4509)
    3. `Bwd Packet Length Std` (correlation: 0.3531)
    4. `Bwd Packet Length Max` (correlation: 0.3452)
    5. `Bwd Packet Length Mean` (correlation: 0.3397)
    6. `Avg Bwd Segment Size` (correlation: 0.3397)
    7. `Packet Length Std` (correlation: 0.3356)
    8. `Max Packet Length` (correlation: 0.3280)
    9. `Packet Length Variance` (correlation: 0.3151)
    10. `Fwd IAT Std` (correlation: 0.3103)
    11. `Packet Length Mean` (correlation: 0.3021)
    12. `Average Packet Size` (correlation: 0.2966)
    13. `Fwd IAT Max` (correlation: 0.2937)

---

## Model Performance Summary

| Configuration | Recall (Attack) | Precision (Attack) | F1-Score (Attack) | Overall Accuracy |
| :--- | :---: | :---: | :---: | :---: |
| **All 77 Features** | **51.48%** | **63.21%** | **56.74%** | **53.00%** |
| **Top 13 Features** | **42.15%** | **51.58%** | **46.39%** | **41.66%** |

---

## Detailed Isolation Forest Reports

### 1. Configuration: All 77 Features

#### Classification Report:
```text
              precision    recall  f1-score   support

  Normal (0)     0.4328    0.5528    0.4855     22731
  Attack (1)     0.6321    0.5148    0.5674     33930

    accuracy                         0.5300     56661
   macro avg     0.5325    0.5338    0.5265     56661
weighted avg     0.5522    0.5300    0.5346     56661

```

#### Confusion Matrix:
*   **True Negatives (TN)**: 12,565
*   **False Positives (FP)**: 10,166
*   **False Negatives (FN)**: 16,464
*   **True Positives (TP)**: 17,466

---

### 2. Configuration: Top 13 Features

#### Classification Report:
```text
              precision    recall  f1-score   support

  Normal (0)     0.3215    0.4092    0.3601     22731
  Attack (1)     0.5158    0.4215    0.4639     33930

    accuracy                         0.4166     56661
   macro avg     0.4187    0.4154    0.4120     56661
weighted avg     0.4378    0.4166    0.4223     56661

```

#### Confusion Matrix:
*   **True Negatives (TN)**: 9,302
*   **False Positives (FP)**: 13,429
*   **False Negatives (FN)**: 19,627
*   **True Positives (TP)**: 14,303
