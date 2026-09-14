# CAT-AD Claim Scope Guardrails

This document defines the wording boundaries for the CAT-AD manuscript. It is
intended to keep the paper defensible for top-tier review by preventing
overclaiming.

## Allowed Claims

- CAT-AD improves robustness in the evaluated ADS-B trajectory anomaly
  detection setting.
- CAT-AD reduces ASR and PV-ASR under the evaluated targeted
  anomalous-to-normal evasion attacks.
- CAT-AD combines physically constrained adversarial training with prediction
  and representation consistency.
- The benchmark includes multi-seed runs, paired comparisons, strict artifact
  verification, preflight checks, and no-download local audit scripts.
- The novelty claim is scoped to the combined ADS-B trajectory security
  protocol and the evaluated artifacts.

## Required Limiting Language

The manuscript must preserve these boundaries:

- Robustness claims are limited to the evaluated perturbation settings and
  threat model.
- Robustness conclusions should remain within the evaluated threat model and
  should not be generalized to untested attacker capabilities.
- Dataset conclusions should remain within the archived one-day decoded ADS-B
  sample, 20 raw aircraft identifiers, 19 filtered aircraft, and evaluated
  aircraft-level splits.
- The paper must not claim transfer to all airspaces, dates, aircraft
  populations, sensor networks, message fields, or operational deployments.
- The paper must not claim that recurrent detectors, PGD, adversarial examples, adversarial
  training, ADS-B anomaly detection, or ADS-B adversarial attacks are new.
- Physical constraints are evaluated proxies for trajectory plausibility, not
  aviation safety certificates.
- Reported robustness is not a certificate against arbitrary adaptive
  attackers or perturbations outside the evaluated budget.
- Formal acceptance is not guaranteed by code or experiments alone.

## Disallowed Claims

Unless a future paper revision adds direct evidence, avoid these claims:

- "first" or "first-ever" absolute novelty claims.
- "state-of-the-art" or "SOTA" superiority claims.
- "certified robustness" or "guaranteed robustness" claims.
- Claims that CAT-AD solves ADS-B security.
- Claims that physical validity metrics prove real-world flight safety.
- Claims that the evaluation covers all possible adaptive attacks.

## Local Check

The no-download audit runs:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_claim_scope.ps1
```

The checker verifies that required limiting language exists in the manuscript
and that the manuscript does not contain a small set of forbidden overclaiming
phrases.
