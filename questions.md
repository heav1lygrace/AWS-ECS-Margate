
# Cloud Security Vendor Evaluation Questions
## Focus: Cloud Security (Not Endpoint)

This document is designed to evaluate cloud security platforms such as Wiz and Qualys with emphasis on:
- Cloud control plane security
- IAM risk
- CSPM
- Attack path modeling
- Kubernetes security
- Cloud-native architecture

---

## 1. Cloud API Coverage

Ask both vendors:

1. Do you use cloud provider APIs only for discovery?
2. Which APIs are consumed (IAM, Resource Manager, CloudTrail, Kubernetes API, Config services)?
3. How often is cloud data refreshed?
4. Is visibility near real-time or scheduled polling?
5. Can polling frequency be customized?

---

## 2. Cloud Asset Inventory

6. Can you automatically discover all cloud accounts, subscriptions, and projects?
7. Can you identify orphaned resources and shadow IT?
8. Do you maintain dependency and relationship mapping?
9. Can you show ownership and environment tagging (prod/dev/test)?

---

## 3. Identity & IAM Risk

10. Can you detect over-permissioned IAM roles?
11. Can you identify unused permissions?
12. Can you detect privilege escalation paths?
13. Can you map Identity → Permission → Resource → Exposure?
14. Can you detect cross-account trust abuse?
15. Do you support AWS IAM, Azure AD, and GCP IAM natively?

---

## 4. Cloud Attack Path Modeling

16. Do you build attack graphs?
17. Can you demonstrate Internet → Public Resource → IAM Role → Sensitive Data paths?
18. Do you correlate network exposure, IAM permissions, vulnerabilities, and secrets?
19. Are attack paths dynamically updated?

---

## 5. Cloud Misconfiguration Detection (CSPM)

20. Do you support CIS Benchmarks?
21. Do you support NIST frameworks?
22. Do you align with AWS Well-Architected Security Pillar?
23. Is misconfiguration detection continuous?
24. Can policies be customized?
25. Can we create custom detection rules?

---

## 6. Kubernetes & Container Cloud Security

26. Do you support managed Kubernetes platforms (EKS, AKS, GKE)?
27. Do you detect control plane misconfigurations?
28. Do you analyze cluster RBAC?
29. Can you detect public services, privileged containers, and host mounts?
30. Can you map Pod → Node → Cloud IAM → External Exposure?

---

## 7. Serverless & PaaS Coverage

31. Do you scan Lambda, Azure Functions, and Cloud Functions?
32. Can you detect over-permissioned serverless functions?
33. Can you identify public triggers?
34. Do you cover managed databases such as RDS, DynamoDB, BigQuery, CosmosDB?

---

## 8. Secrets & Data Exposure

35. Can you detect public storage buckets?
36. Can you detect exposed snapshots?
37. Can you detect secrets stored in cloud resources?
38. Can you correlate public exposure combined with sensitive data?

---

## 9. Cloud Logging & Visibility Integration

39. Can you ingest CloudTrail, Azure Activity Logs, and GCP Audit Logs?
40. Do you detect suspicious cloud activity patterns?
41. Can alerts integrate with SOAR platforms?

---

## Qualys-Specific Cloud Architecture Challenge Questions

42. Which cloud security features require agents?
43. Can CSPM function without installing VM agents?
44. Can IAM risk analysis work without agents?
45. Do you correlate IAM permissions, network exposure, and vulnerabilities in one risk engine?
46. Is Kubernetes security native or bolt-on?
47. How do you handle auto-scaling workloads, ephemeral containers, and serverless resources?

---

## Proof of Concept Validation Tasks

Request live demonstrations:

48. Show public S3 bucket detection.
49. Show over-permissioned IAM role detection.
50. Show attack path from Internet → EC2 → IAM Role → RDS.
51. Show Kubernetes cluster risk detection.
52. Show remediation workflow integration.

---

## Cloud Architecture Alignment

53. Which AWS Security Pillars do you align with?
54. Do you integrate with AWS Organizations?
55. Do you integrate with Control Tower?
56. Do you support Service Control Policies (SCPs)?
57. Can you enforce cloud guardrails?

---

## Cloud-Native Evaluation Framework

| Capability | Cloud Native | Legacy |
|------------|-------------|--------|
| IAM Graph Analysis | Yes | No |
| Attack Path Modeling | Yes | No |
| Agentless Architecture | Yes | No |
| Kubernetes Native Support | Yes | Partial |
| API Driven Architecture | Yes | No |
| Compliance Only Focus | No | Yes |

---

## Recommendation

Prioritize cloud-native platforms that:

- Operate agentlessly
- Build attack graphs
- Analyze IAM risk
- Support Kubernetes natively
- Integrate deeply with cloud APIs

Use traditional vulnerability scanners only as secondary hygiene tools.

