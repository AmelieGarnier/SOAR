![Wazuh](https://img.shields.io/badge/Wazuh-4.13-blue?style=flat-square) ![Suricata](https://img.shields.io/badge/Suricata-6.0.10-orange?style=flat-square) ![Debian](https://img.shields.io/badge/%F0%9F%90%A7_Debian-13-lightgrey?style=flat-square) ![OpenSearch](https://img.shields.io/badge/OpenSearch-Indexer-blue?style=flat-square&logo=opensearch) ![VirusTotal](https://img.shields.io/badge/%CE%A3_VirusTotal-Int%C3%A9gr%C3%A9-blueviolet?style=flat-square) ![SIEM](https://img.shields.io/badge/SIEM-Single--Node-green?style=flat-square) ![FIM](https://img.shields.io/badge/%F0%9F%93%8B_FIM-Whodata-purple?style=flat-square)
![Active Response](https://img.shields.io/badge/Active_Response-Brute_Force-red?style=flat-square) ![Docs](https://img.shields.io/badge/%F0%9F%93%96_Docs-Runbooks-grey?style=flat-square)

# SOAR Lab — TheHive 4 + Cortex + Shuffle

Lab de sécurité automatisé déployé sur deux VMs Debian 13, intégrant détection, enrichissement et réponse automatique aux incidents.

## Architecture

| VM | IP | Composants |
|----|----|------------|
| VM Wazuh | `192.168.1.50` | Wazuh 4.13 + Suricata 7.0.10 |
| VM SOAR | `192.168.1.60` | TheHive 4 + Cortex 3 + Shuffle (Docker) |

## Stack

| Composant | Rôle | Port |
|-----------|------|------|
| **Shuffle** | Orchestrateur SOAR — workflows automatisés | 3443 (HTTPS) |
| **TheHive 4** | Gestion des incidents et des cas de sécurité | 9000 |
| **Cortex** | Enrichissement automatique — AbuseIPDB, VirusTotal | 9001 |
| **Elasticsearch** | Base de données TheHive + Cortex | interne |
| **OpenSearch** | Base de données Shuffle | interne |
| **Wazuh Manager** | SIEM — corrélation des alertes, envoi webhook | — |

## Use Cases implémentés

| # | Use Case | MITRE | Statut |
|---|----------|-------|--------|
| 1 | Brute Force SSH (Hydra) | T1110 / TA0006 | ✅ |
| 2 | Scan de ports Suricata (nmap) | T1046 / TA0007 | ✅ |
| 3 | Exfiltration DNS | T1048.003 / TA0010 | ✅ |

## Flux automatisé

```
[Wazuh 192.168.1.50]
  Suricata → eve.json → Wazuh Manager
      │ webhook HTTP
      ▼
[Shuffle 192.168.1.60]
    ├──► TheHive (case + observable IP)
    ├──► AbuseIPDB (score de réputation)
    ├──► Condition score > 50 ?
    │       ├── OUI → Wazuh API → Active Response (blocage iptables)
    │       └── NON → TheHive (note IP non malveillante)
    └──► Cortex → AbuseIPDB analyzer
```

## KPIs mesurés

| KPI | Valeur | Cible |
|-----|--------|-------|
| MTTD | 20 s | < 30 s |
| MTTR | < 1 s | < 120 s |
| Taux blocage auto | 100 % | > 80 % |
| Disponibilité stack | 100 % | > 99 % |

## Documentation

- [Runbook SOAR v9](docs/runbook-soar-v9.md) — Installation complète, configuration, workflows Shuffle, troubleshooting

## Accès interfaces

| Interface | URL | Identifiants par défaut |
|-----------|-----|------------------------|
| TheHive | http://192.168.1.60:9000 | `admin@thehive.local` / `secret` |
| Cortex | http://192.168.1.60:9001 | À créer au premier accès |
| Shuffle | https://192.168.1.60:3443 | À créer au premier accès |
| Wazuh Dashboard | https://192.168.1.50 | `admin` / `admin` |
