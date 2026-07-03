# Mathematical Framework — Three Theorems for the Paper

*Drafted 2026-07-03. Every claim here maps to a measurable quantity in `validate_theory.py`.*

Notation used throughout:

- $S$ — scalar anomaly score produced by a detector (orientation: higher = more anomalous)
- $Y \in \{0,1\}$ — true class (1 = attack, 0 = normal)
- $F_A(t) = P(S \le t \mid Y{=}1)$, $F_N(t) = P(S \le t \mid Y{=}0)$ — class-conditional CDFs of the score
- $\mathrm{TPR}(t) = P(S > t \mid Y{=}1) = 1 - F_A(t)$
- $\mathrm{FPR}(t) = P(S > t \mid Y{=}0) = 1 - F_N(t)$
- Youden's J at threshold $t$: $J(t) = \mathrm{TPR}(t) - \mathrm{FPR}(t)$

---

## Theorem 1 — The KS Ceiling for Threshold Detectors

### Statement

**Theorem 1.** *For any detector that decides "attack" iff $S > t$ for some threshold $t$ (or iff $S \le t$, i.e., either orientation), the maximum achievable Youden's J satisfies*

$$\sup_t\; |J(t)| \;=\; \sup_t\; |F_N(t) - F_A(t)| \;=\; \mathrm{KS}(F_A, F_N).$$

*No threshold choice, score rescaling, or monotone calibration can exceed this bound.*

### Proof

For the "flag high" orientation:

$$J(t) = \mathrm{TPR}(t) - \mathrm{FPR}(t) = \big(1 - F_A(t)\big) - \big(1 - F_N(t)\big) = F_N(t) - F_A(t).$$

Taking the supremum over $t$ gives $\sup_t J(t) = \sup_t\,[F_N(t) - F_A(t)]$. For the reversed orientation ("flag low"), $J'(t) = F_A(t) - F_N(t)$, and the best over both orientations is $\sup_t |F_N(t) - F_A(t)|$, which is by definition the two-sample Kolmogorov–Smirnov statistic. Monotone transformations of $S$ leave both CDFs' ordering intact, hence leave KS invariant. $\blacksquare$

### Corollaries (each is a testable number)

**C1.1 — Balanced accuracy ceiling.**
$\mathrm{BA}(t) = \tfrac{1}{2}(\mathrm{TPR} + \mathrm{TNR}) = \tfrac{1}{2}(1 + J(t))$, hence

$$\max_t \mathrm{BA}(t) = \frac{1 + \mathrm{KS}}{2}.$$

*Empirical checkpoint:* AE on CTU-13 has KS = 0.860 → BA ceiling = **0.930**. Observed accuracy on the balanced test set: **0.929**. The detector operates at its theoretical ceiling — the threshold is already optimal; only changing the score distribution (the representation) can improve it. Similarly IF: KS = 0.445 → ceiling 0.7225; observed 0.656.

**C1.2 — Recall at a false-alarm budget.**
Since $J(t) \le \mathrm{KS}$ for every $t$:

$$\mathrm{TPR}(t) \;\le\; \mathrm{FPR}(t) + \mathrm{KS}.$$

At an operational false-alarm budget $\mathrm{FPR} \le \alpha$: recall $\le \alpha + \mathrm{KS}$. For IF on CTU-13 at a 5% false-alarm budget: recall $\le$ 0.495. **No tuning of IF can catch more than half the attacks at SOC-acceptable false-alarm rates.** This single line justifies the entire paper.

**C1.3 — AUC lower-bounds KS.**
$\mathrm{AUC} = \int_0^1 \mathrm{TPR}\, d\mathrm{FPR} \le \int_0^1 (\mathrm{FPR} + \mathrm{KS})\, d\mathrm{FPR} = \tfrac{1}{2} + \mathrm{KS}$, hence

$$\mathrm{KS} \;\ge\; \mathrm{AUC} - \tfrac{1}{2}.$$

Checkpoints: AE (AUC 0.978, KS 0.860 ≥ 0.478 ✓); IF (AUC 0.677, KS 0.445 ≥ 0.177 ✓).

### Honest scope limitation (reviewers will ask)

Threshold rules decide via a half-line $\{S > t\}$. For an *arbitrary* measurable decision region $C$, the bound is the total variation distance $\mathrm{TV}(P_A^S, P_N^S) = \sup_C |P_A(S \in C) - P_N(S \in C)| \ge \mathrm{KS}$, with equality iff the likelihood ratio is monotone in $S$ (MLR property). All deployed anomaly detectors are threshold rules, so KS is the operative ceiling; we state the TV refinement for completeness.

---

## Theorem 2 — OR-Fusion of Conditionally Independent Detectors

Motivation: the temporal-features experiment showed flow-AE and temporal-AE catch *different* attack families. When is a union of two heads provably better than either alone?

### Setup

Two detectors with flag events $B_1 = \{S_1 > t_1\}$, $B_2 = \{S_2 > t_2\}$, with per-head operating points $(\mathrm{TPR}_i, \mathrm{FPR}_i)$. **Assumption (CI):** conditional independence given each class,

$$P(B_1 \cap B_2 \mid Y{=}y) = P(B_1 \mid Y{=}y)\, P(B_2 \mid Y{=}y), \quad y \in \{0,1\}.$$

The OR-fused detector flags iff $B_1 \cup B_2$.

### Statement

**Theorem 2.** *Under (CI), the OR-fused detector satisfies:*

**(a) Miss-product law.** Misses multiply:
$$1 - \mathrm{TPR}_{\mathrm{OR}} = (1 - \mathrm{TPR}_1)(1 - \mathrm{TPR}_2).$$

**(b) Subadditive false alarms.**
$$\mathrm{FPR}_{\mathrm{OR}} = 1 - (1-\mathrm{FPR}_1)(1-\mathrm{FPR}_2) \;\le\; \mathrm{FPR}_1 + \mathrm{FPR}_2.$$

**(c) Fusion-benefit criterion.** $J_{\mathrm{OR}} > J_1$ (adding head 2 helps) **iff**
$$(1 - \mathrm{TPR}_1)\,\mathrm{TPR}_2 \;>\; (1 - \mathrm{FPR}_1)\,\mathrm{FPR}_2 .$$

### Proof

(a), (b): immediate from (CI) applied to the complement events: $P(\overline{B_1} \cap \overline{B_2} \mid y) = P(\overline{B_1}\mid y)P(\overline{B_2} \mid y)$ — a miss of the union is a simultaneous miss of both heads.

(c): $J_{\mathrm{OR}} = \mathrm{TPR}_{\mathrm{OR}} - \mathrm{FPR}_{\mathrm{OR}} = (1-\mathrm{FPR}_1)(1-\mathrm{FPR}_2) - (1-\mathrm{TPR}_1)(1-\mathrm{TPR}_2)$ and $J_1 = (1-\mathrm{FPR}_1) - (1-\mathrm{TPR}_1)$. Subtracting:

$$J_{\mathrm{OR}} - J_1 = (1-\mathrm{TPR}_1)\,\mathrm{TPR}_2 - (1-\mathrm{FPR}_1)\,\mathrm{FPR}_2. \qquad \blacksquare$$

Interpretation of (c): the left side is head 2's *incremental catch* — the fraction of attacks head 1 misses that head 2 recovers. The right side is head 2's *incremental noise* on traffic head 1 correctly passes. Fuse iff catch > noise. Equivalently: fuse iff $\dfrac{\mathrm{TPR}_2}{\mathrm{FPR}_2} > \dfrac{1-\mathrm{FPR}_1}{1-\mathrm{TPR}_1}$.

*Empirical checkpoint (UNSW-NB15, 95th-pct thresholds, both heads at FPR ≈ 0.05):*
flow head TPR₁ ≈ 0.086, temporal head TPR₂ ≈ 0.440.
Criterion: $(1-0.086) \times 0.440 = 0.402 \;>\; (1-0.05)\times 0.05 = 0.0475$ — satisfied by 8.5×.
Predicted union recall under (CI): $1 - (1-0.086)(1-0.440) = 0.488$. The validation script measures the actual union recall and compares.

### When is OR the *optimal* fusion rule?

Under (CI), the joint likelihood ratio factorises: $\Lambda(s_1, s_2) = \Lambda_1(s_1)\Lambda_2(s_2)$. By Neyman–Pearson, the optimal rule thresholds $\log \Lambda_1 + \log \Lambda_2$ — additive score fusion, of which OR is a corner approximation.

**Proposition 2.1 (mixture limit).** *If the attack population is a mixture $P_A = \pi_1 P_A^{(1)} + \pi_2 P_A^{(2)}$ where subfamily $k$ is invisible to the other head ($\Lambda_{3-k} \equiv 1$ on subfamily $k$), the Neyman–Pearson region degenerates to the union $B_1 \cup B_2$ — OR is exactly optimal.*

This is precisely our situation: Worms/Generic are visible only to the flow head; Backdoor/Analysis only to the temporal head. Heterogeneous attack families are the regime where OR-fusion is principled, not a heuristic.

### Diagnostics for the (CI) assumption

**Miss-redundancy coefficient** (one number per attack type):

$$\rho_{\mathrm{miss}} = \frac{P(\overline{B_1} \cap \overline{B_2} \mid Y{=}1)}{P(\overline{B_1} \mid Y{=}1)\, P(\overline{B_2} \mid Y{=}1)}.$$

$\rho = 1$: independent blind spots (miss-product law holds exactly). $\rho > 1$: correlated blind spots — both heads miss the *same* attacks, union gains less than predicted (expected for Shellcode). $\rho < 1$: complementary — union gains more than predicted.

**Conditional mutual information** (score-level, stronger than the binary version):

$$I(S_1; S_2 \mid Y) = \sum_y P(Y{=}y) \sum_{i,j} p_y(i,j)\, \log \frac{p_y(i,j)}{p_y(i)\, p_y(j)}$$

estimated by quantile-binning each score into 10 bins within each class. $I \approx 0$ bits → heads carry non-redundant information → union justified; large $I$ → heads are redundant → average/learned fusion instead. This turns "diversity helps" from folklore into a measured quantity.

---

## Theorem 3 — Parameter-Free Thresholds via Extreme Value Theory

Motivation: the 95th-percentile threshold is arbitrary and cannot be extrapolated — a percentile estimate at level $1-q$ needs $\gtrsim 1/q$ samples and ignores tail shape. EVT gives a principled threshold for *any* target false-positive rate, including rates deeper than the data resolution.

### Statement

**Theorem 3 (Pickands–Balkema–de Haan, applied).** *Let $S_N$ be the anomaly score of normal traffic with CDF $F$ in the maximum domain of attraction of an extreme value distribution (satisfied by essentially all continuous distributions encountered in practice). Then the excess distribution over a high threshold $u$,*

$$F_u(x) = P(S_N - u \le x \mid S_N > u),$$

*converges uniformly, as $u \to x_F$, to a Generalized Pareto Distribution:*

$$G_{\xi,\sigma}(x) = 1 - \Big(1 + \frac{\xi x}{\sigma}\Big)^{-1/\xi} \quad (\xi \ne 0), \qquad G_{0,\sigma}(x) = 1 - e^{-x/\sigma}.$$

### The POT threshold recipe

1. Choose $u$ = empirical $(1 - p_u)$-quantile of *training normal* scores (we use $p_u = 0.10$, i.e., the 90th percentile).
2. Fit $(\hat\xi, \hat\sigma)$ by maximum likelihood on the $n_u$ excesses $\{s_i - u : s_i > u\}$.
3. For a target false-positive rate $q$, solve $P(S_N > t_q) = p_u \cdot \big(1 + \hat\xi (t_q - u)/\hat\sigma\big)^{-1/\hat\xi} = q$:

$$\boxed{\; t_q = u + \frac{\hat\sigma}{\hat\xi}\left[\left(\frac{p_u}{q}\right)^{\hat\xi} - 1\right] \;} \qquad (\hat\xi \ne 0), \qquad t_q = u + \hat\sigma \ln\frac{p_u}{q} \quad (\hat\xi = 0).$$

**Guarantee:** the realized FPR converges to $q$, with confidence intervals available from the asymptotic normality of the GPD MLE (delta method). The shape parameter $\hat\xi$ is itself diagnostic: $\hat\xi > 0$ means the normal-score tail is heavy — exactly the regime where percentile thresholds are systematically over-optimistic about false alarms.

**Why this matters operationally:** with $n = 56{,}000$ normal training flows, the naive percentile method cannot target FPR below $\sim 1/n \approx 2\times10^{-5}$ and is noisy well before that; the GPD extrapolates the tail analytically, so a $q = 10^{-4}$ threshold is computable and calibrated. Deployment story: run 24 h of clean traffic through the detector, fit the GPD, dial in the false-alarm budget your SOC can absorb. Zero hyperparameters.

*Empirical checkpoint:* fit the GPD on UNSW-NB15 training-normal MSE; for $q \in \{0.05, 0.01, 0.005, 0.001, 10^{-4}\}$ compare realized FPR on the held-out test normals against the target, for both the GPD threshold and the naive percentile threshold.

---

## How the Three Theorems Compose (the paper's system claim)

$$\text{Stage 1 heads (thresholds set by Thm 3)} \;\xrightarrow{\text{OR-fusion justified by Thm 2}}\; \text{fused detector} \;\xrightarrow{\text{bounded by Thm 1}}\; \text{ceiling } \mathrm{KS}_{\mathrm{fused}}$$

1. **Theorem 1** says the only way to raise the ceiling is to change score distributions — motivating multiple anomaly notions (representations), not more tuning.
2. **Theorem 2** says *which* notions to combine (conditionally independent ones, measured by $\rho_{\mathrm{miss}}$ and $I(S_1;S_2|Y)$) and *how* (OR in the heterogeneous-family regime, Prop. 2.1), and predicts the fused recall in closed form.
3. **Theorem 3** removes the last free parameter, making the fused system deployable with a guaranteed false-alarm budget.

The experimental sections then verify each closed-form prediction on CTU-13 and UNSW-NB15.

---

## References for this section

- W. J. Youden, "Index for rating diagnostic tests," *Cancer*, 1950. (Youden's J)
- A. N. Kolmogorov (1933); N. Smirnov (1939). (KS statistic)
- J. Neyman, E. S. Pearson, "On the problem of the most efficient tests of statistical hypotheses," *Phil. Trans. R. Soc. A*, 1933.
- J. Pickands, "Statistical inference using extreme order statistics," *Ann. Statist.*, 1975.
- A. Balkema, L. de Haan, "Residual life time at great age," *Ann. Probab.*, 1974.
- A. Siffer, P.-A. Fouque, A. Termier, C. Largouët, "Anomaly detection in streams with extreme value theory," *KDD*, 2017. (SPOT/DSPOT — POT thresholds for anomaly scores)
- T. M. Cover, J. A. Thomas, *Elements of Information Theory*, 2nd ed., Wiley, 2006. (mutual information)
