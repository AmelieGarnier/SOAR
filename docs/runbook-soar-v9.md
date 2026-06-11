# Runbook SOAR — TheHive 4 + Cortex + Shuffle (v8)

> **Architecture 2 VMs :**
> - **VM Wazuh** : `192.168.1.50` — Wazuh 4.13.x + Suricata 7.0.10
> - **VM SOAR** : `192.168.1.60`
>
> **Prérequis :** Wazuh et Suricata opérationnels (voir runbooks précédents)
> **Stack SOAR :** TheHive 4 + Cortex 3 + Shuffle — déployés via Docker sur la VM SOAR

---

## Présentation de la stack SOAR

| Composant | Rôle | Port | VM |
|-----------|------|------|----||
| **Shuffle** | Orchestrateur SOAR — workflows automatisés | 3443 (HTTPS) | SOAR |
| **TheHive 4** | Gestion des incidents et des cas de sécurité | 9000 | SOAR |
| **Cortex** | Enrichissement automatique — AbuseIPDB, VirusTotal | 9001 | SOAR |
| **Elasticsearch** | Base de données TheHive + Cortex | interne | SOAR |
| **OpenSearch** | Base de données Shuffle | interne | SOAR |
| **Wazuh Manager** | SIEM — corrélation des alertes, envoi webhook | — | Wazuh |

> ℹ️ **Pourquoi TheHive 4 et non TheHive 5 ?**
> TheHive 5 (StrangeBee) est limité à **2 utilisateurs actifs** en version gratuite.
> TheHive 4 est 100% **open source (AGPL-3.0)**, sans restriction d'utilisateurs.
> Il n'utilise **pas Cassandra** — Elasticsearch seul suffit, ce qui simplifie la stack et réduit la consommation RAM.

### Flux complet

```
[VM Wazuh 192.168.1.50]
  Suricata → eve.json → Wazuh logcollector → Wazuh Manager
      │
      │  webhook HTTP
      ▼
[VM SOAR 192.168.1.60]
  Shuffle
    ├──► TheHive (case + observable IP créés automatiquement)
    ├──► AbuseIPDB (enrichissement IP)
    ├──► Condition score > 50 ?
    │       ├── OUI → Wazuh API → Active Response (blocage iptables)
    │       └── NON → TheHive (note "IP non malveillante")
    └──► Cortex → AbuseIPDB analyzer (rapport dans TheHive)
```

### Matrice de décision — choix des outils

| Composant | Outil retenu | Score | Alternative écartée |
|---|---|---|---|
| Orchestrateur SOAR | Shuffle | 24/30 | n8n (17/30) — pas de connecteurs natifs TheHive |
| Gestion incidents | TheHive 4 | — | TheHive 5 — limite 2 users, Cassandra requis |
| SIEM/EDR | Wazuh | — | Splunk — propriétaire, 8+ Go RAM |
| Enrichissement | Cortex 3 | — | HTTP direct — pas de traçabilité dans TheHive |

---

## Table des matières

1. [Création et préparation de la VM SOAR](#1-création-et-préparation-de-la-vm-soar)
2. [Installation de Docker](#2-installation-de-docker)
3. [Déploiement TheHive 4 + Cortex](#3-déploiement-thehive-4--cortex)
4. [Déploiement Shuffle](#4-déploiement-shuffle)
5. [Vérifier la connectivité entre les deux VMs](#5-vérifier-la-connectivité-entre-les-deux-vms)
6. [Configuration Active Response sur Wazuh](#6-configuration-active-response-sur-wazuh)
7. [Connexion Wazuh → Shuffle (webhooks)](#7-connexion-wazuh--shuffle-webhooks)
8. [Configuration TheHive et Cortex](#8-configuration-thehive-et-cortex)
9. [Construction du workflow Shuffle — Use case #1 Brute Force SSH](#9-construction-du-workflow-shuffle--use-case-1-brute-force-ssh)
10. [Activation des analyzers Cortex](#10-activation-des-analyzers-cortex)
11. [Test de validation — Attaque brute force SSH avec Hydra](#11-test-de-validation--attaque-brute-force-ssh-avec-hydra)
12. [Test complet de la chaîne SOAR](#12-test-complet-de-la-chaîne-soar)
13. [Supervision avec Zabbix](#13-supervision-avec-zabbix)
14. [Opérations courantes](#14-opérations-courantes)
15. [Troubleshooting](#15-troubleshooting)
16. [Améliorations Niveau 1 — Maturité professionnelle](#16-améliorations-niveau-1--maturité-professionnelle)
17. [Améliorations Niveau 2 — Use case #2 Scan de ports Suricata](#17-améliorations-niveau-2--use-case-2-scan-de-ports-suricata)
18. [Améliorations Niveau 3 — Version avancée](#18-améliorations-niveau-3--version-avancée)

---

## 1. Création et préparation de la VM SOAR

### Specs VirtualBox

| Ressource | Valeur |
|-----------|--------|
| OS | Debian 13 64-bit |
| RAM | 8 Go minimum (12 Go recommandés) |
| CPU | 4 cœurs |
| Disque | 50 Go minimum |
| Réseau | **Mode pont (Bridged) — obligatoire** |

> ⚠️ Le réseau **doit être en mode pont**. Sans ça, la VM SOAR et la VM Wazuh ne peuvent pas communiquer.

### Récupérer l'IP de la VM SOAR

```bash
ip a | grep "inet " | grep -v 127
```

### Préparer le système

```bash
sudo -i
export PATH=$PATH:/sbin:/usr/sbin
echo 'export PATH=$PATH:/sbin:/usr/sbin' >> /root/.bashrc
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
apt update && apt upgrade -y
apt install -y curl gnupg micro jq procps
```

### Paramètre noyau requis

Elasticsearch et OpenSearch refusent de démarrer sans ce paramètre.

```bash
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
sysctl vm.max_map_count
# → 262144
```

---

## 2. Installation de Docker

> Sur la **VM SOAR**.

```bash
apt install -y ca-certificates curl gnupg lsb-release

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable docker
systemctl start docker
```

---

## 3. Déploiement TheHive 4 + Cortex

> Sur la **VM SOAR**.

### Préparer les répertoires

```bash
mkdir -p ~/soar-stack/thehive/config
mkdir -p ~/soar-stack/cortex/config
mkdir -p /tmp/cortex-jobs
chmod 777 /tmp/cortex-jobs
cd ~/soar-stack
```

### Créer les fichiers de configuration Cortex

> ⚠️ **Étape obligatoire.** Sans ces fichiers, Cortex crashe silencieusement au démarrage.

```bash
cat > ~/soar-stack/cortex/config/logback.xml << 'EOF'
<configuration>
  <conversionRule conversionWord="coloredLevel" converterClass="play.api.libs.logback.ColoredLevel" />
  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
    <encoder>
      <pattern>%date [%level] from %logger in %thread - %message%n%xException</pattern>
    </encoder>
  </appender>
  <logger name="play" level="INFO" />
  <logger name="application" level="INFO" />
  <root level="INFO">
    <appender-ref ref="STDOUT" />
  </root>
</configuration>
EOF

cat > ~/soar-stack/cortex/config/application.conf << 'EOF'
search {
  uri = "http://elasticsearch:9200"
}
job {
  directory = /tmp/cortex-jobs
}
EOF
```

### Nettoyer les éventuels containers orphelins

> ⚠️ Si tu migres depuis une ancienne stack TheHive 5, Cassandra peut tourner en arrière-plan.
> TheHive 4 le détecterait et tenterait de s'y connecter au lieu d'Elasticsearch → crash en boucle.

```bash
docker compose down
docker rm -f cassandra 2>/dev/null || true

# Vérifier qu'il ne reste aucune trace
docker ps -a | grep cassandra
grep -n "cassandra" ~/soar-stack/docker-compose.yml
# → les deux commandes doivent retourner vide
```

### Créer le fichier docker-compose.yml

> ⚠️ Heap TheHive réduite à `-Xms512m -Xmx512m` pour éviter le CPU starvation sur VM avec RAM limitée.

```bash
cat > ~/soar-stack/docker-compose.yml << 'EOF'
services:

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - es_data:/usr/share/elasticsearch/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9200"]
      interval: 30s
      timeout: 10s
      retries: 5

  thehive:
    image: thehiveproject/thehive4:latest
    container_name: thehive
    depends_on:
      elasticsearch:
        condition: service_healthy
    ports:
      - "9000:9000"
    environment:
      - "JVM_OPTS=-Xms512m -Xmx512m"
    volumes:
      - thehive_data:/opt/thehive/data
    restart: unless-stopped

  cortex:
    image: thehiveproject/cortex:3
    container_name: cortex
    depends_on:
      elasticsearch:
        condition: service_healthy
    ports:
      - "9001:9001"
    environment:
      - job_directory=/tmp/cortex-jobs
    volumes:
      - ./cortex/config:/etc/cortex
      - /var/run/docker.sock:/var/run/docker.sock
      - /tmp/cortex-jobs:/tmp/cortex-jobs
      - ./cortex/Cortex-Analyzers:/opt/cortex/neurons
    restart: unless-stopped

volumes:
  es_data:
  thehive_data:
EOF
```

### Lancer la stack

```bash
cd ~/soar-stack
docker compose up -d
watch docker compose ps
docker compose logs -f thehive
# Attendre "Listening for HTTP on /0.0.0.0:9000"
```

### Vérifier l'accès

```bash
curl -s http://localhost:9000/api/status | jq .versions
curl -s http://localhost:9001/api/status
```

| Interface | URL | Identifiants par défaut |
|-----------|-----|------------------------|
| TheHive | http://192.168.1.60:9000 | `admin@thehive.local` / `secret` |
| Cortex | http://192.168.1.60:9001 | À créer au premier accès |

---

## 4. Déploiement Shuffle

> Sur la **VM SOAR**.

### Cloner le dépôt

```bash
cd ~/soar-stack
git clone https://github.com/Shuffle/Shuffle shuffle-deploy
cd shuffle-deploy
```

### Forcer la version OpenSearch compatible

```bash
sed -i 's|opensearchproject/opensearch:.*|opensearchproject/opensearch:2.14.0|g' docker-compose.yml
grep opensearch docker-compose.yml | grep image
# → image: opensearchproject/opensearch:2.14.0
```

### Configurer le fichier .env

> ⚠️ `OUTER_HOSTNAME` doit être l'IP réelle, pas `shuffle-backend`.

```bash
sed -i 's/OUTER_HOSTNAME=shuffle-backend/OUTER_HOSTNAME=192.168.1.60/' .env
sed -i 's|BASE_URL=http://shuffle-backend:5001|BASE_URL=https://192.168.1.60:3443|' .env

grep -E "OUTER_HOSTNAME|BASE_URL" .env
# → BASE_URL=https://192.168.1.60:3443
# → OUTER_HOSTNAME=192.168.1.60

# Mot de passe OpenSearch obligatoire depuis 2.12+
echo "OPENSEARCH_INITIAL_ADMIN_PASSWORD=Shuffle@Admin1234!" >> .env
```

### Préparer et lancer

```bash
swapoff -a
docker run --rm -v shuffle-deploy_shuffle-database:/data busybox chown -R 1000:1000 /data
docker compose up -d
sleep 60
docker compose logs opensearch | grep -i "started" | tail -3
```

### Accès à Shuffle

```
✅ https://192.168.1.60:3443   ← correct (accepter le cert auto-signé)
❌ http://192.168.1.60:3001    ← redirige vers GitHub
```

Au premier accès, créer un compte administrateur directement dans l'interface.

---

## 5. Vérifier la connectivité entre les deux VMs

```bash
# VM SOAR → VM Wazuh
ping -c 3 192.168.1.50
curl -k -s https://192.168.1.50:55000/ | jq .title
# → "Wazuh API REST"

# VM Wazuh → VM SOAR
ping -c 3 192.168.1.60
curl -s http://192.168.1.60:9000/api/status | jq .versions
```

---

## 6. Configuration Active Response sur Wazuh

> Sur la **VM Wazuh** (`192.168.1.50`).

### 6.1 Configurer le Manager (ossec.conf)

```bash
micro /var/ossec/etc/ossec.conf
```

La section `<active-response>` doit contenir **trois blocs** :

```xml
<!-- Bloc 1 : déclenchement sur règle custom -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>600</timeout>
</active-response>

<!-- Bloc 2 : déclenchement sur brute force SSH -->
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763</rules_id>
  <timeout>600</timeout>
</active-response>

<!-- Bloc 3 : OBLIGATOIRE pour le déclenchement via API Wazuh (Shuffle) -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <timeout>600</timeout>
</active-response>
```

> ⚠️ Le **bloc 3 sans `<rules_id>`** est indispensable pour que l'API puisse déclencher l'Active Response depuis Shuffle. Sans lui → erreur `1652`.

```bash
systemctl restart wazuh-manager
```

### 6.2 Configurer l'agent Linux (ossec.conf sur chaque agent)

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <timeout>600</timeout>
</active-response>
```

```bash
systemctl restart wazuh-agent
```

### 6.3 S'assurer qu'iptables est dans le PATH de l'agent

```bash
which iptables || echo "introuvable"

# Si introuvable :
echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' >> /etc/environment
export PATH=$PATH:/usr/sbin
systemctl restart wazuh-agent
```

### 6.4 Vérifier le fichier ar.conf

```bash
cat /var/ossec/etc/shared/ar.conf
# → doit contenir "firewall-drop600 - firewall-drop - 600" sans rules_id
```

### 6.5 Tester l'Active Response via l'API

> ⚠️ Le nom de commande dans l'API est `firewall-drop600` (pas `firewall-drop`).
> L'IP doit être dans `alert.data.srcip`, pas dans `arguments`.

```bash
curl -k -s -X PUT \
  -H "Authorization: Bearer $(curl -k -s -u wazuh-wui:wazuh-wui 'https://192.168.1.50:55000/security/user/authenticate?raw=true')" \
  -H "Content-Type: application/json" \
  "https://192.168.1.50:55000/active-response?agents_list=003" \
  -d '{"command":"firewall-drop600","arguments":[],"alert":{"data":{"srcip":"1.2.3.4"}}}'

# Résultat attendu :
# {"affected_items": ["003"], "total_affected_items": 1, "total_failed_items": 0}

# Vérifier sur l'agent
tail -5 /var/ossec/logs/active-responses.log
iptables -L -n | grep 1.2.3.4
```

---

## 7. Connexion Wazuh → Shuffle (webhooks)

Shuffle expose **deux ports distincts** :

| Port | Protocole | Usage |
|------|-----------|-------|
| `3443` | HTTPS | Interface web — navigateur |
| `3001` | HTTP | Réception des webhooks — machines |

> ⚠️ Toujours utiliser **`http://` port `3001`** pour les webhooks Wazuh. Wazuh ne peut pas valider le certificat auto-signé de Shuffle sur le port 3443 — la connexion échoue silencieusement.

### Créer les webhooks dans Shuffle

Pour chaque workflow :

1. `https://192.168.1.60:3443` → **Workflows** → **+ Create Workflow**
2. Cliquer sur le nœud **Webhook** → copier l'URL
3. Activer le workflow (toggle vert en haut à droite)

URL format : `http://192.168.1.60:3001/api/v1/hooks/webhook_XXXXXXXX`

### Configurer les intégrations dans Wazuh

```bash
micro /var/ossec/etc/ossec.conf
```

Ajouter les deux blocs `<integration>` dans `<ossec_config>` :

```xml
<!-- Use case #1 — Brute force SSH → workflow wazuh-alert-triage -->
<integration>
  <name>shuffle</name>
  <hook_url>http://192.168.1.60:3001/api/v1/hooks/webhook_XXXXXXXX</hook_url>
  <rule_id>5763</rule_id>
  <alert_format>json</alert_format>
</integration>

<!-- Use case #2 — Scan de ports Suricata → workflow suricata-portscan-triage -->
<integration>
  <name>shuffle</name>
  <hook_url>http://192.168.1.60:3001/api/v1/hooks/webhook_0bc3468b-8190-424b-9dec-e9979fd64c8b</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

> ⚠️ **Trois erreurs fréquentes à éviter :**
> 1. **`https://` et port `3443`** → webhook jamais reçu, Wazuh ne valide pas le cert auto-signé.
> 2. **`<level>3</level>` au lieu de `<rule_id>`** → déclenche sur toutes les alertes niveau 3+, y compris la règle 651 dont le payload ne contient pas `srcip`.
> 3. **`<rule_id>651</rule_id>`** → la règle 651 est le log de confirmation du blocage firewall-drop, pas la détection SSH.

```bash
systemctl restart wazuh-manager
sleep 10
systemctl status wazuh-manager | head -3
```

### Corriger l'URL si elle est en https://3443

```bash
sed -i 's|https://192.168.1.60:3443|http://192.168.1.60:3001|' /var/ossec/etc/ossec.conf
grep "hook_url" /var/ossec/etc/ossec.conf
systemctl restart wazuh-manager
```

### Tester la réception des webhooks

```bash
systemctl restart wazuh-manager
sleep 10
curl http://www.testmyids.com
sleep 8
tail -5 /var/ossec/logs/integrations.log
```

---

## 8. Configuration TheHive et Cortex

### 8.1 Créer une organisation dans TheHive

1. `http://192.168.1.60:9000` → login `admin@thehive.local` / `secret`
2. **Admin** → **Organisations** → **New Organisation** → `SOC-Lab`
3. **Admin** → **Users** → **New User** dans `SOC-Lab` :

| Champ | Valeur |
|-------|--------|
| Login | `shuffle@soc.local` |
| Rôle | `analyst` |
| Organisation | `SOC-Lab` |

### 8.2 Générer la clé API TheHive pour Shuffle

1. Se connecter avec `shuffle@soc.local`
2. Icône profil → **API Key** → **Create** → copier la clé

### 8.3 Initialiser Cortex

```bash
cd ~/soar-stack
curl -s -X POST http://localhost:9001/api/maintenance/migrate
sleep 10
```

Se connecter sur `http://192.168.1.60:9001` → créer un compte admin → créer organisation `SOC-Lab` → **API Keys** → **Créer** → copier la clé.

### 8.4 Lier Cortex à TheHive via application.conf

> ⚠️ Dans TheHive 4, il n'y a **pas** de menu Admin → Cortex dans l'interface.
> La liaison se fait uniquement via le fichier de configuration.

```bash
cat > ~/soar-stack/thehive/config/application.conf << 'EOF'
db.janusgraph {
  storage.backend = berkeleyje
  storage.directory = /data/db
}

index.search {
  backend = elasticsearch
  hostname = ["elasticsearch"]
  index-name = thehive
}

storage {
  provider = localfs
  localfs.location = /data/files
}

play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule
cortex {
  servers = [
    {
      name = local
      url = "http://cortex:9001"
      auth {
        type = "bearer"
        key = "COLLE_TA_CLE_API_CORTEX_ICI"
      }
    }
  ]
}
EOF
```

```bash
cd ~/soar-stack
docker compose restart thehive
sleep 60
docker compose logs thehive | grep -E "Cortex|started|ERROR" | tail -10
```

Vérifier la liaison : **TheHive → Admin → Platform Management** → status `thehive-cortex` doit être **OK**.

---

## 9. Construction du workflow Shuffle — Use case #1 Brute Force SSH

### Nom du workflow : `wazuh-alert-triage`

### Architecture complète (nœuds renommés v6)

```
[Wazuh-Webhook]
    │
    ├──► [TheHive-CreateCase]    POST /api/v1/case → 201
    ├──► [Discord-Notify]        POST webhook Discord → 204
    ├──► [AbuseIPDB-Score]       GET api.abuseipdb.com → score
    │
    └──► Condition : $AbuseIPDB-Score.body.data.abuseConfidenceScore > 50
              │
              ├── OUI → [Wazuh-Auth] → [Cortex-AbuseIPDB] → [Tools-Repeat] → [Wazuh-ActiveResponse]
              └── NON → [TheHive-NoteIPClean]
    │
    └──► [TheHive-AddObservable]  POST /api/case/{id}/artifact → 201
```

### Tableau de nommage des nœuds

| Nom v6 | Type | Rôle |
|---|---|---|
| `Wazuh-Webhook` | Webhook trigger | Point d'entrée Wazuh |
| `TheHive-CreateCase` | HTTP POST | Crée le case |
| `Discord-Notify` | HTTP POST | Notification Discord |
| `AbuseIPDB-Score` | HTTP GET | Score de réputation IP |
| `Wazuh-Auth` | HTTP GET | Authentification API Wazuh |
| `Cortex-AbuseIPDB` | HTTP POST | Lance l'analyzer Cortex |
| `Tools-Repeat` | Shuffle Tools | Boucle d'attente |
| `Wazuh-ActiveResponse` | HTTP PUT | Déclenche le blocage iptables |
| `TheHive-NoteIPClean` | HTTP PATCH | Note IP non malveillante |
| `TheHive-AddObservable` | HTTP POST | Ajoute l'observable IP |

### Comment renommer un nœud dans Shuffle

1. Cliquer sur le nœud
2. Panneau droite → nom en haut → cliquer → modifier → Entrée
3. Mettre à jour toutes les variables qui référencent ce nœud
4. **Save** après chaque renommage avant de passer au suivant

### Variables à mettre à jour après renommage

| Nœud renommé | Dans quel nœud | Remplacer | Par |
|---|---|---|---|
| `Http 1` → `TheHive-CreateCase` | `TheHive-NoteIPClean` | `$http_1.body._id` | `$TheHive-CreateCase.body._id` |
| `Http 1` → `TheHive-CreateCase` | `TheHive-AddObservable` | `$http_1.body._id` | `$TheHive-CreateCase.body._id` |
| `Http 2` → `AbuseIPDB-Score` | `Condition` | `$http_2.body.data.abuseConfidenceScore` | `$AbuseIPDB-Score.body.data.abuseConfidenceScore` |
| `Http 3` → `Wazuh-Auth` | `Wazuh-ActiveResponse` | `$http_3.body` | `$Wazuh-Auth.body` |

---

### Nœud TheHive-CreateCase

| Champ | Valeur |
|-------|--------|
| URL | `http://192.168.1.60:9000/api/v1/case` |
| Méthode | `POST` |
| Header `Authorization` | `Bearer CLE_API_THEHIVE` |
| Header `Content-Type` | `application/json` |

Corps :
```json
{
  "title": "Wazuh Alert — $exec.all_fields.rule.description",
  "severity": 2,
  "flag": false,
  "tlp": 2,
  "pap": 2,
  "description": "## Alerte Wazuh — Brute Force SSH\n\n**Règle :** $exec.rule_id\n**Agent :** $exec.all_fields.agent.name\n**IP attaquant :** $exec.all_fields.data.srcip\n**IP agent :** $exec.all_fields.agent.ip\n**Log brut :** $exec.text\n\n---\n\n## MITRE ATT&CK\n\n| Champ | Valeur |\n|---|---|\n| Tactique | Credential Access (TA0006) |\n| Technique | Brute Force (T1110) |\n| Sous-technique | Password Guessing (T1110.001) |\n| Outil observé | SSH |\n\n---\n\n## Contexte\n\nDétection automatique via Wazuh rule 5763. Enrichissement AbuseIPDB en cours.",
  "tags": ["wazuh", "brute-force", "ssh", "T1110", "T1110.001", "TA0006", "Credential-Access", "automated"]
}
```

Résultat attendu : `status 201`. L'ID du case est dans `$TheHive-CreateCase.body._id`.

> ⚠️ **Variables Shuffle obligatoires** — les chemins courts (`$exec.agent.name`, `$exec.data.srcip`) retournent vide car la règle 5763 structure ses données sous `all_fields`. Toujours préfixer par `$exec.all_fields.*`.

---

### Nœud Discord-Notify

> ⚠️ Discord n'accepte pas `application/json` sur les webhooks — utiliser `application/x-www-form-urlencoded`.

| Champ | Valeur |
|-------|--------|
| URL | `https://discord.com/api/webhooks/TON_WEBHOOK_DISCORD` |
| Méthode | `POST` |
| Header `Content-Type` | `application/x-www-form-urlencoded` |

Body :
```
content=🚨 **ALERTE SÉCURITÉ — Brute Force SSH**%0A%0A🔴 **Source :** $exec.all_fields.data.srcip%0A🛡️ **Cible :** $exec.all_fields.agent.name ($exec.all_fields.agent.ip)%0A📋 **Règle Wazuh :** $exec.rule_id%0A📁 **Case TheHive :** $TheHive-CreateCase.body._id%0A%0A⚙️ *Analyse AbuseIPDB en cours — blocage si score > 50...*
```

Résultat attendu : `status 204`.

---

### Nœud AbuseIPDB-Score

| Champ | Valeur |
|-------|--------|
| URL | `https://api.abuseipdb.com/api/v2/check?ipAddress=$exec.all_fields.data.srcip&maxAgeInDays=90` |
| Méthode | `GET` |
| Header `Key` | `CLE_API_ABUSEIPDB` |
| Header `Accept` | `application/json` |

Le score de réputation est dans `$AbuseIPDB-Score.body.data.abuseConfidenceScore`.

> ℹ️ **Test en lab avec IP privée** : remplacer temporairement par `185.220.101.45` (nœud Tor — score > 90 garanti) pour valider la branche OUI. Remettre `$exec.all_fields.data.srcip` ensuite.

---

### Nœud Condition — Score > 50 ?

```
Si $AbuseIPDB-Score.body.data.abuseConfidenceScore larger than 50
    → branche OUI : Wazuh-Auth → Cortex-AbuseIPDB → Tools-Repeat → Wazuh-ActiveResponse
    → branche NON : TheHive-NoteIPClean
```

**Mécanisme Flip Branch dans Shuffle :**

| Flèche | Condition | Flip Branch | Résultat |
|---|---|---|---|
| → `Wazuh-Auth` | `score larger than 50` | Non | S'exécute si score > 50 |
| → `TheHive-NoteIPClean` | `score larger than 50` | **Oui** | S'exécute si score ≤ 50 |

**Point critique — variable parasite :**

```
INCORRECT : $abuseipdb-score.0.body.data.abuseConfidenceScore
CORRECT   : $abuseipdb-score.body.data.abuseConfidenceScore
```

Fix : éditeur de condition → icône ↗ → supprimer le `.0.` → Submit → Save.

---

### Nœud Wazuh-Auth

| Champ | Valeur |
|-------|--------|
| URL | `https://192.168.1.50:55000/security/user/authenticate?raw=true` |
| Méthode | `GET` |
| Username | `wazuh-wui` |
| Password | `wazuh-wui` |
| Verify SSL | `False` |

Le token JWT est dans `$Wazuh-Auth.body`.

---

### Nœud Cortex-AbuseIPDB

> ⚠️ **Point critique.** L'API Cortex n'accepte pas le nom lisible (`AbuseIPDB_2_0`) — elle exige l'**ID interne hexadécimal**.

**Récupérer l'ID interne de l'analyzer :**

```bash
curl -s -H "Authorization: Bearer CLE_API_CORTEX" \
  http://192.168.1.60:9001/api/analyzer | jq '[.[] | select(.name | contains("AbuseIPDB")) | {name, id}]'
```

Résultat :
```json
[{"name": "AbuseIPDB_2_0", "id": "ce9544d9d6e229e407d7c43145c6d6c4"}]
```

> ℹ️ L'ID change si Cortex est réinitialisé. Refaire cette commande après toute réinitialisation.

| Champ | Valeur |
|---|---|
| URL | `http://192.168.1.60:9001/api/analyzer/ID_INTERNE_ICI/run` |
| Méthode | `POST` |
| Header `Authorization` | `Bearer CLE_API_CORTEX` |
| Header `Content-Type` | `application/json` |

Body :
```json
{
  "data": "$exec.all_fields.data.srcip",
  "dataType": "ip",
  "tlp": 2,
  "message": "Enrichissement automatique — brute force SSH"
}
```

---

### Nœud Wazuh-ActiveResponse

> ⚠️ Commande : `firewall-drop600` (pas `firewall-drop`). IP dans `alert.data.srcip`.

| Champ | Valeur |
|-------|--------|
| URL | `https://192.168.1.50:55000/active-response?agents_list=$exec.agent.id` |
| Méthode | `PUT` |
| Header `Authorization` | `Bearer $Wazuh-Auth.body` |
| Header `Content-Type` | `application/json` |
| Verify SSL | `False` |

Corps :
```json
{
  "command": "firewall-drop600",
  "arguments": [],
  "alert": {
    "data": {
      "srcip": "$exec.all_fields.data.srcip"
    }
  }
}
```

Résultat attendu : `status 200`, `total_affected_items: 1`, `total_failed_items: 0`.

---

### Nœud TheHive-NoteIPClean (branche NON)

> ⚠️ TheHive 4 n'a pas d'endpoint `/comment` ni `/task`. La seule méthode : PATCH sur le case pour mettre à jour la description. Résultat attendu : **status 204**.

| Champ | Valeur |
|-------|--------|
| URL | `http://192.168.1.60:9000/api/v1/case/$TheHive-CreateCase.body._id` |
| Méthode | `PATCH` |
| Header `Authorization` | `Bearer CLE_API_THEHIVE` |
| Header `Content-Type` | `application/json` |

Corps :
```json
{
  "description": "IP $exec.all_fields.data.srcip analysée — score AbuseIPDB : $AbuseIPDB-Score.body.data.abuseConfidenceScore/100. Aucun blocage appliqué."
}
```

---

### Nœud TheHive-AddObservable

> ⚠️ **TheHive 4 uniquement.** L'endpoint v1 `/api/v1/case/{id}/observable` retourne `204` sans body.
> Utiliser l'endpoint v0 `/api/case/{id}/artifact` qui retourne `201` avec l'objet complet.

| Champ | Valeur |
|---|---|
| URL | `http://192.168.1.60:9000/api/case/$TheHive-CreateCase.body._id/artifact` |
| Méthode | `POST` |
| Header `Authorization` | `Bearer CLE_API_THEHIVE` |
| Header `Content-Type` | `application/json` |

Body :
```json
{
  "dataType": "ip",
  "data": "$exec.all_fields.data.srcip",
  "message": "IP source brute force SSH",
  "tlp": 2,
  "ioc": true
}
```

---

## 10. Activation des analyzers Cortex

### Installer les neurons Cortex

```bash
ls ~/soar-stack/cortex/Cortex-Analyzers/

# Si absent :
cd ~/soar-stack/cortex
git clone https://github.com/TheHive-Project/Cortex-Analyzers.git
```

Configurer les chemins dans `application.conf` :

```bash
echo 'analyzer.path = ["/opt/cortex/neurons/analyzers"]
responder.path = ["/opt/cortex/neurons/responders"]' >> ~/soar-stack/cortex/config/application.conf

tail -5 ~/soar-stack/cortex/config/application.conf

cd ~/soar-stack
docker compose restart cortex
```

### Se connecter en orgadmin pour accéder aux Analyzers

> ⚠️ Les onglets **Analyzers** et **Responders** ne sont visibles que depuis un compte **orgadmin**, pas depuis le compte admin global.

1. Cortex (admin global) → **Organizations → SOC-Lab → Users → orgadmin → New password**
2. Se reconnecter avec `orgadmin`
3. **Organizations → SOC-Lab** → onglets **Analyzers** et **Responders** visibles

### Clés API nécessaires

| Service | Gratuit | URL | Quota |
|---------|---------|-----|-------|
| AbuseIPDB | ✅ | https://abuseipdb.com | 1 000 req/jour |
| VirusTotal | ✅ | https://virustotal.com | 500 req/jour |

### Activer AbuseIPDB dans Cortex

**Organization** → **Analyzers** → chercher `AbuseIPDB` → **Enable** → renseigner la clé API → Sauvegarder.

### Activer VirusTotal dans Cortex

**VirusTotal_GetReport_3_1** — ce module analyse IPs, hashes, domaines et URLs.

### Vérifier la liaison TheHive → Cortex

**TheHive → Admin → Platform Management** → status `thehive-cortex` doit être **OK**.

---

## 11. Test de validation — Attaque brute force SSH avec Hydra

> ⚠️ À réaliser uniquement en environnement de test contrôlé.

### Architecture du test

| Machine | IP | Rôle |
|---------|-----|------|
| Attaquante | 192.168.1.22 | Lance Hydra |
| Victime | 192.168.1.58 | Cible SSH + agent Wazuh |
| Wazuh Manager | 192.168.1.50 | Détection + Active Response |

### Lancer l'attaque

```bash
apt install -y hydra pwgen
pwgen 8 10 > password-list.txt
hydra -l debian13 -P password-list.txt 192.168.1.58 ssh
```

### Résultats attendus dans Wazuh Dashboard

| Règle | Description |
|-------|-------------|
| 5760 | Tentatives d'authentification SSH échouées |
| 5763 | Détection d'attaque par force brute SSH |
| 651 | Blocage IP par firewall-drop |
| 652 | Déblocage IP après expiration du timeout |

### Vérifier le blocage

```bash
iptables -L -n | grep 192.168.1.22
# → DROP  all  --  192.168.1.22  0.0.0.0/0

tail -f /var/ossec/logs/active-responses.log
# → active-response/bin/firewall-drop: Ended  (après 600 s)
```

---

## 12. Test complet de la chaîne SOAR

### Checklist de validation — Use case #1 (Brute Force SSH)

```
[✅] TheHive-CreateCase      → 201, tags T1110/TA0006, tableau MITRE dans description
[✅] Discord-Notify          → 204, message visible sur Discord
[✅] AbuseIPDB-Score         → 200, abuseConfidenceScore présent
[✅] Condition               → branche OUI si score > 50, NON sinon
[✅] Wazuh-Auth              → 200, token JWT
[✅] Cortex-AbuseIPDB        → 200, job dans Cortex Jobs History
[✅] Wazuh-ActiveResponse    → 200, AR sent to all agents
[✅] TheHive-NoteIPClean     → SKIPPED si branche OUI
[✅] TheHive-AddObservable   → 201 endpoint v0 /api/case/{id}/artifact
[✅] iptables                → DROP sur IP source
```

---

## 13. Supervision avec Zabbix

### Éléments à superviser

| Élément | Méthode | Seuil d'alerte |
|---------|---------|----------------|
| Service wazuh-manager | Port TCP 1514 | Down > 1 min |
| Service wazuh-indexer | Port TCP 9200 | Down > 1 min |
| Container thehive | Port TCP 9000 | Down > 1 min |
| Container cortex | Port TCP 9001 | Down > 1 min |
| Container shuffle-frontend | Port TCP 3443 | Down > 1 min |
| RAM VM SOAR | Agent Zabbix | > 90% |
| CPU VM SOAR | Agent Zabbix | > 85% pendant 5 min |
| Disque VM SOAR | Agent Zabbix | > 80% |

### Installation de l'agent Zabbix — VM SOAR

```bash
wget https://repo.zabbix.com/zabbix/6.4/debian/pool/main/z/zabbix-release/zabbix-release_6.4-1+debian12_all.deb
dpkg -i zabbix-release_6.4-1+debian12_all.deb
apt update && apt install -y zabbix-agent2

micro /etc/zabbix/zabbix_agent2.conf
# → Server=IP_VM_ZABBIX
# → ServerActive=IP_VM_ZABBIX
# → Hostname=SOAR

systemctl enable zabbix-agent2
systemctl start zabbix-agent2
```

### Checks réseau Zabbix (Simple check)

```
net.tcp.service[tcp,192.168.1.50,1514]   → wazuh-manager
net.tcp.service[tcp,192.168.1.50,9200]   → wazuh-indexer
net.tcp.service[tcp,192.168.1.60,9000]   → thehive
net.tcp.service[tcp,192.168.1.60,9001]   → cortex
net.tcp.service[tcp,192.168.1.60,3443]   → shuffle
```

---

## 14. Opérations courantes

### État de la stack

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
cd ~/soar-stack && docker compose ps
cd ~/soar-stack/shuffle-deploy && docker compose ps
```

### Logs

```bash
docker compose logs -f thehive
docker compose logs -f cortex
cd ~/soar-stack/shuffle-deploy && docker compose logs -f backend
```

### Procédure de redémarrage après reboot

```bash
cd ~/soar-stack && docker compose up -d
cd ~/soar-stack/shuffle-deploy && docker compose up -d
sleep 120
docker ps --format "table {{.Names}}\t{{.Status}}"

# Si elasticsearch est unhealthy
docker compose -f ~/soar-stack/docker-compose.yml restart elasticsearch
sleep 60
docker compose -f ~/soar-stack/docker-compose.yml restart thehive
sleep 60
curl -s http://localhost:9000/api/status | jq .versions
```

---

## 15. Troubleshooting

### Active Response : erreur 1652 — commande non définie

```bash
grep -c "active-response" /var/ossec/etc/ossec.conf
# → doit retourner au moins 3
cat /var/ossec/etc/shared/ar.conf | grep "firewall-drop600"
grep -A 3 "firewall-drop" /var/ossec/etc/ossec.conf
```

### Active Response : iptables introuvable

```bash
find /usr -name "iptables" 2>/dev/null
echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' >> /etc/environment
export PATH=$PATH:/usr/sbin
systemctl restart wazuh-agent
```

### Variables Shuffle vides — TheHive case sans données / AbuseIPDB 422

**Cause :** Trigger configuré sur `<level>3</level>` → déclenche sur la règle 651 dont le payload ne contient pas `srcip`.

```xml
<!-- Avant (incorrect) -->
<level>3</level>

<!-- Après (correct) -->
<rule_id>5763</rule_id>
```

| Variable incorrecte | Variable correcte |
|---|---|
| `$exec.data.srcip` | `$exec.all_fields.data.srcip` |
| `$exec.agent.name` | `$exec.all_fields.agent.name` |
| `$exec.agent.ip` | `$exec.all_fields.agent.ip` |
| `$exec.rule.description` | `$exec.all_fields.rule.description` |

### TheHive inaccessible — CPU starvation

```bash
# docker-compose.yml
JVM_OPTS=-Xms512m -Xmx512m

cd ~/soar-stack && docker compose restart thehive
sleep 120
curl -s http://127.0.0.1:9000/api/status | jq .versions
```

### TheHive crash en boucle — `param is ---es-uri-`

```bash
sed -i '/command:/d' ~/soar-stack/docker-compose.yml
docker compose down && docker compose up -d
```

### Shuffle HTTPS inaccessible

```bash
sed -i 's/OUTER_HOSTNAME=shuffle-backend/OUTER_HOSTNAME=192.168.1.60/' ~/soar-stack/shuffle-deploy/.env
sed -i 's|BASE_URL=http://shuffle-backend:5001|BASE_URL=https://192.168.1.60:3443|' ~/soar-stack/shuffle-deploy/.env
cd ~/soar-stack/shuffle-deploy && docker compose down && docker compose up -d
```

### OpenSearch (Shuffle) crash — version incompatible

```bash
sed -i 's|opensearchproject/opensearch:.*|opensearchproject/opensearch:2.14.0|g' \
  ~/soar-stack/shuffle-deploy/docker-compose.yml
cd ~/soar-stack/shuffle-deploy
docker compose down
docker volume rm shuffle-deploy_shuffle-database
docker run --rm -v shuffle-deploy_shuffle-database:/data busybox chown -R 1000:1000 /data
docker compose up -d
```

### Cortex : "Error: user init not found"

```bash
cd ~/soar-stack
curl -s -X POST http://localhost:9001/api/maintenance/migrate
sleep 10
curl -s -X POST http://localhost:9001/api/user \
  -H "Content-Type: application/json" \
  -d '{"login":"admin","name":"Admin","roles":["superadmin"],"password":"AdminCortex1234!"}'
docker compose restart thehive
```

### Cortex : worker not found (404)

```bash
# Cause B — récupérer l'ID interne
curl -s -H "Authorization: Bearer CLE_API_CORTEX" \
  http://192.168.1.60:9001/api/analyzer | jq '[.[] | select(.name | contains("AbuseIPDB")) | {name, id}]'

# Cause C — image Docker absente
docker pull ghcr.io/thehive-project/abuseipdb:2
```

### TheHive-AddObservable retourne 204 sans body

Utiliser l'endpoint v0 `/api/case/{id}/artifact` au lieu de `/api/v1/case/{id}/observable`.

### Wazuh-indexer timeout au démarrage

```bash
systemctl restart wazuh-indexer && sleep 30
systemctl restart wazuh-manager && sleep 10
systemctl restart wazuh-dashboard
```

**Solution permanente :**
```bash
mkdir -p /etc/systemd/system/wazuh-indexer.service.d/
cat > /etc/systemd/system/wazuh-indexer.service.d/override.conf << 'EOF'
[Service]
ExecStartPre=/bin/sleep 30
EOF
systemctl daemon-reload
```

### Réinitialiser complètement la stack

> ⚠️ Toutes les données seront perdues.

```bash
cd ~/soar-stack && docker compose down -v
cd ~/soar-stack/shuffle-deploy && docker compose down -v
cd ~/soar-stack && docker compose up -d
cd ~/soar-stack/shuffle-deploy && docker compose up -d
```

---

## 16. Améliorations Niveau 1 — Maturité professionnelle

| Réf | Amélioration | Type | Statut |
|---|---|---|---|
| L1-1 | MITRE ATT&CK sur les cases TheHive | Sécurité / GRC | ✅ Implémenté (section 9) |
| L1-2 | Script de healthcheck stack | Exploitation | ✅ Implémenté |
| L1-3 | Tableau de KPI | Documentation | ✅ Implémenté |
| L1-4 | Cortex intégré dans le workflow Shuffle | Technique | ✅ Implémenté (section 9) |
| L1-5 | Schéma d'architecture | Documentation | ✅ Implémenté (section 9) |

### 16.1 Script de healthcheck stack (L1-2)

```bash
cat > /root/check_stack.sh << 'EOF'
#!/bin/bash
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
ERRORS=0

check() {
  local NAME="$1" CMD="$2" EXPECTED="$3" RESULT
  RESULT=$(eval "$CMD" 2>/dev/null)
  if echo "$RESULT" | grep -qE "$EXPECTED"; then
    echo "[$TIMESTAMP] OK  $NAME"
  else
    echo "[$TIMESTAMP] KO  $NAME — $(echo $RESULT | head -c 60)"
    ERRORS=$((ERRORS + 1))
  fi
}

echo "[$TIMESTAMP] ── Healthcheck SOAR ──"
check "elasticsearch" "docker exec elasticsearch curl -sf http://localhost:9200/_cluster/health" '"status"'
check "thehive"       "curl -sf http://localhost:9000/api/status"  '"versions"'
check "cortex"        "curl -sf http://localhost:9001/api/status"  'Cortex'
check "shuffle"       "curl -skf https://localhost:3443"           "."
check "wazuh-api"     "curl -kfs -o /dev/null -w '%{http_code}' https://192.168.1.50:55000/ --max-time 5" '401'
echo "[$TIMESTAMP] ── $ERRORS erreur(s) ──"
exit $ERRORS
EOF

chmod +x /root/check_stack.sh

# Planifier en cron
crontab -e
# → */5 * * * * /root/check_stack.sh >> /var/log/soar_health.log 2>&1
```

### 16.2 Tableau de KPI (L1-3)

| KPI | Run 1 | Cible |
|---|---|---|
| MTTD (s) | **20** | < 30 s |
| MTTR (s) | **< 1** | < 120 s |
| Taux blocage auto (%) | **100** | > 80 % |
| Disponibilité stack (%) | **100** | > 99 % |

| Date | Attaque | IP source | Score AbuseIPDB | Bloquée | MTTD | MTTR |
|---|---|---|---|---|---|---|
| 2026-05-17 | Hydra SSH | 192.168.1.22 | 100 (IP test) | Oui | 20 s | < 1 s |

---

## 17. Améliorations Niveau 2 — Use case #2 Scan de ports Suricata

| Réf | Amélioration | Type | Statut |
|---|---|---|---|
| L2-1 | 2ème use case — scan de ports Suricata | Technique | ✅ Implémenté |
| L2-2 | Déduplication / rate limiting | Technique | 🔄 En cours |
| L2-3 | Dashboard OpenSearch | Démonstration | 🔄 En cours |
| L2-4 | Rapport HTML automatisé | Exploitation | 🔄 En cours |
| L2-5 | Matrice de décision | Documentation | ✅ Implémenté (section intro) |

### 17.1 Architecture du flux

```
[Kali — nmap -sS]
      │
      ▼
[Suricata — eve.json — alerte ET SCAN / sid:9000001]
      │
      ▼
[Wazuh — logcollector ingère eve.json — règle 100002 → webhook]
      │
      ▼
[Shuffle — workflow suricata-portscan-triage]
      │
      ├──► TheHive — case T1046 / TA0007
      ├──► Discord — notification
      └──► AbuseIPDB — enrichissement IP source
```

### 17.2 Configuration Suricata — règle custom

#### Pourquoi une règle custom ?

En production, les règles ET SCAN standard ciblent `$EXTERNAL_NET -> $HOME_NET`. Dans ce lab, toutes les machines sont en `192.168.1.0/24` — Kali est traitée comme `$HOME_NET` → les règles ne se déclenchent pas.

**Solution :** règle custom `sid:9000001` qui déclenche sur n'importe quel SYN scan quelle que soit l'IP source.

```bash
sed -i '/sid:9000001/d' /var/lib/suricata/rules/suricata.rules
echo 'alert tcp any any -> $HOME_NET any (msg:"ET SCAN Portscan detected"; flags:S; flow:stateless; threshold: type threshold, track by_src, count 50, seconds 3; classtype:attempted-recon; sid:9000001; rev:1; metadata:created_at 2026_05_17;)' >> /var/lib/suricata/rules/suricata.rules
systemctl restart suricata
```

**Solution propre :** modifier `HOME_NET` dans `suricata.yaml` :

```yaml
HOME_NET: "[192.168.1.50/32,192.168.1.58/32,192.168.1.60/32]"
```

### 17.3 Configuration Wazuh — règle custom 100002

Ajouter dans `/var/ossec/etc/rules/local_rules.xml` :

```xml
<group name="local,suricata,">
  <rule id="100002" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature">SCAN</field>
    <description>Suricata: Port scan detected</description>
    <group>suricata,scan</group>
  </rule>
</group>
```

> ⚠️ La règle doit impérativement être à l'intérieur d'un tag `<group>`. Une règle orpheline provoque `ERROR: Invalid root element "rule"`.

```bash
systemctl restart wazuh-manager
```

### 17.4 Workflow Shuffle — suricata-portscan-triage

Créer un **nouveau workflow distinct** dans Shuffle.

**Body TheHive-CreateCase :**
```json
{
  "title": "Suricata — Scan réseau depuis $exec.all_fields.data.src_ip",
  "severity": 2,
  "flag": false,
  "tlp": 2,
  "pap": 2,
  "description": "## Alerte Suricata — Scan de ports\n\n**Signature :** $exec.all_fields.data.alert.signature\n**IP source :** $exec.all_fields.data.src_ip\n**IP cible :** $exec.all_fields.data.dest_ip\n**Agent Wazuh :** $exec.all_fields.agent.name\n\n---\n\n## MITRE ATT&CK\n\n| Champ | Valeur |\n|---|---|\n| Tactique | Discovery (TA0007) |\n| Technique | Network Service Discovery (T1046) |\n| Outil observé | nmap / scanner réseau |",
  "tags": ["suricata", "portscan", "nmap", "T1046", "TA0007", "Discovery", "automated"]
}
```

> ⚠️ Pour Suricata, la variable IP source est `data.src_ip` (format eve.json) et **non** `data.srcip` (format syslog SSH).

### 17.5 Fixes post-déploiement appliqués en production

#### Problème 1 — TheHive bloqué sur un reindex job

```bash
# Passer les replicas à 0 → cluster passe GREEN
docker exec elasticsearch curl -s -X PUT "http://localhost:9200/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index":{"number_of_replicas":0}}'

docker exec elasticsearch curl -s "http://localhost:9200/_cluster/health?pretty" | grep status
```

#### Problème 2 — Faux positifs Discord (192.168.1.60)

```bash
echo "suppress gen_id 1, track by_src, ip 192.168.1.60" >> /etc/suricata/threshold.config
sudo systemctl restart suricata
```

#### Problème 3 — Alertes scan multiples par run nmap

```bash
python3 << 'EOF'
with open('/var/lib/suricata/rules/suricata.rules', 'r') as f:
    lines = f.readlines()
new_rule = 'alert tcp !$HOME_NET any -> $HOME_NET any (msg:"ET SCAN Portscan detected"; flags:S; flow:stateless; threshold: type limit, track by_src, count 1, seconds 60; classtype:attempted-recon; sid:9000001; rev:3; metadata:created_at 2026_05_17;)\n'
for i, line in enumerate(lines):
    if 'sid:9000001' in line:
        lines[i] = new_rule
        break
with open('/var/lib/suricata/rules/suricata.rules', 'w') as f:
    f.writelines(lines)
print("Done")
EOF

sudo kill -USR2 $(pidof suricata)
```

### 17.6 Dashboard SOAR — Wazuh Dashboard

#### Visualisations à créer

| # | Type | Titre | Champ clé |
|---|---|---|---|
| 1 | Horizontal Bar | Top IPs — Brute Force SSH | `data.srcip`, filtre `rule.id:5763` |
| 2 | Line | Alertes SOAR — Timeline | `@timestamp`, split `rule.id` |
| 3 | Pie | MITRE ATT&CK — Techniques détectées | `rule.mitre.technique` |
| 4 | Vertical Bar | Use cases SSH vs Portscan | `rule.description` |
| 5 | Heatmap | Intensité des alertes par heure | `@timestamp` interval Hour, color Reds |
| 6 | Metric | Brute Force SSH détectés | filtre `rule.id:5763` |
| 7 | Metric | Scans réseau détectés | filtre `rule.id:100002` |
| 8 | Metric | Total alertes SOAR | sans filtre |

**Titre dashboard :** `SOAR Lab — Supervision des incidents`
Rafraîchissement : **10 secondes** — Plage : **Last 7 days**

### 17.7 Simulation d'attaques pour peupler le dashboard

```bash
cat > /root/simulate_attacks.sh << 'EOF'
#!/bin/bash
FAKE_IPS=("45.33.32.156" "185.220.101.1" "194.165.16.28" "91.240.118.172"
           "103.99.0.122" "200.158.68.20" "41.223.57.14" "61.177.172.55")
USERS=("root" "admin" "ubuntu" "debian" "user" "test" "oracle" "postgres")

for IP in "${FAKE_IPS[@]}"; do
  USER=${USERS[$RANDOM % ${#USERS[@]}]}
  PORT=$((40000 + RANDOM % 9999))
  DATE=$(date "+%b %e %H:%M:%S")
  for i in $(seq 1 12); do
    echo "${DATE} $(hostname) sshd[$$]: Failed password for ${USER} from ${IP} port ${PORT} ssh2" \
      >> /var/log/auth.log
    sleep 0.05
  done
  echo "  → ${IP} injectée (user: ${USER})"
  sleep 2
done
EOF
chmod +x /root/simulate_attacks.sh

# Lancer 3 vagues
/root/simulate_attacks.sh && sleep 120 && \
/root/simulate_attacks.sh && sleep 120 && \
/root/simulate_attacks.sh
```

### 17.8 Checklist Niveau 2

```
[✅] L2-5 : Matrice de décision — voir section intro
[✅] L2-1 : Règle Suricata active — sid:9000001 (threshold: limit 1/60s, !$HOME_NET)
[✅] L2-1 : Règle Wazuh custom 100002 — filtre sur signature SCAN
[✅] L2-1 : Intégration Wazuh — rule_id 100002 → webhook_0bc3468b-...
[✅] L2-1 : Workflow suricata-portscan-triage créé dans Shuffle
[✅] L2-1 : Test nmap → alerte Suricata → case TheHive T1046/TA0007
[✅] L2-2 : Rate limiting — Suricata threshold + Wazuh rule 100002
[✅] L2-3 : Dashboard "SOAR Lab — Supervision des incidents" — 8 visualisations
[ ]  L2-4 : Script daily_report.sh + cron 7h + HTTP :8080
```

---

## 18. Améliorations Niveau 3 — Version avancée

| # | Amélioration | Objectif | Difficulté | Impact soutenance |
|---|---|---|---|---|
| L3-1 | 3ème use case : exfiltration DNS | Détecter connexions DNS suspectes via Suricata | ⭐⭐⭐ | 🔥🔥🔥 |
| L3-2 | Gestion des secrets | Stocker clés API dans .env chiffré + Docker secrets | ⭐⭐ | 🔥🔥 |
| L3-3 | Playbook de fermeture de case | Auto-fermer un case si l'IP n'est plus active après 24h | ⭐⭐⭐ | 🔥🔥 |
| L3-4 | Simulation d'attaque scriptée | Script Bash rejouant des scénarios d'attaque | ⭐⭐ | 🔥🔥🔥 |

---

## 18.1 L3-1 — Use case #3 : Exfiltration DNS ✅

**MITRE ATT&CK :** T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol / TA0010 — Exfiltration

### Règle Suricata custom — sid:9000002

```bash
echo 'alert dns any any -> any 53 (msg:"ET CUSTOM DNS Exfiltration - Long subdomain query"; dns.query; content:"."; pcre:"/^[a-z0-9]{20,}\./i"; threshold: type limit, track by_src, count 1, seconds 60; classtype:trojan-activity; sid:9000002; rev:1; metadata:created_at 2026_05_24;)' >> /var/lib/suricata/rules/suricata.rules

sudo kill -USR2 $(pidof suricata)
```

### Règle Wazuh custom 100003

Ajouter dans `/var/ossec/etc/rules/local_rules.xml` :

```xml
<group name="suricata,dns,exfiltration,">
  <rule id="100003" level="12">
    <if_sid>86601</if_sid>
    <field name="alert.signature">DNS Exfiltration</field>
    <description>Suricata: DNS exfiltration attempt detected</description>
    <mitre>
      <id>T1048.003</id>
    </mitre>
  </rule>
</group>
```

```bash
systemctl restart wazuh-manager
```

### Intégration Wazuh → Shuffle

```xml
<!-- Use case #3 — Exfiltration DNS → workflow dns-exfil-triage -->
<integration>
  <name>shuffle</name>
  <hook_url>https://192.168.1.60:3443/api/v1/hooks/webhook_604a8518-77c8-4ef5-b9c5-231bd257e1db</hook_url>
  <rule_id>100003</rule_id>
  <alert_format>json</alert_format>
</integration>
```

### Workflow Shuffle — dns-exfil-triage

**Body TheHive-CreateCase-DNS :**
```json
{
  "title": "Suricata — Exfiltration DNS depuis $exec.data.src_ip",
  "severity": 3,
  "flag": true,
  "tlp": 3,
  "tags": ["suricata", "dns", "exfiltration", "T1048.003", "TA0010", "automated"],
  "description": "## Alerte Suricata — Exfiltration DNS\n\n**IP source :** $exec.data.src_ip\n**Signature :** $exec.data.alert.signature\n\n## MITRE ATT&CK\n\n| Tactique | Exfiltration (TA0010) |\n|---|---|\n| Technique | T1048.003 |"
}
```

> ⚠️ Leçons prod : ne pas mettre `/api/case` dans l'URL TheHive. Utiliser `$exec.data.src_ip` (pas `$exec.all_fields`). Utiliser `%0A` pour les sauts de ligne Discord.

### Test du workflow

```bash
curl -k -X POST https://192.168.1.60:3443/api/v1/hooks/webhook_604a8518-77c8-4ef5-b9c5-231bd257e1db \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {"id": "100003", "level": 12, "description": "Suricata: DNS exfiltration attempt detected"},
    "data": {"src_ip": "80.82.77.33", "alert": {"signature": "DNS Exfiltration", "severity": 1}},
    "agent": {"name": "Wazuh"}
  }'
```

> L'IP `80.82.77.33` est un scanner connu avec score AbuseIPDB > 90.

### Checklist L3-1

```
[✅] Règle Suricata sid:9000002 — détection sous-domaines longs
[✅] Règle Wazuh 100003 — level 12, T1048.003
[✅] Intégration Wazuh → Shuffle — rule_id 100003
[✅] Workflow dns-exfil-triage créé dans Shuffle
[✅] TheHive case créé — severity H, TLP:RED, tags T1048.003/TA0010
[✅] AbuseIPDB enrichissement — score > 50 → Discord
[✅] Test curl → case TheHive + notification Discord
```

---

## 18.2 L3-2 — Gestion des secrets

```bash
# Créer et chiffrer le fichier de secrets
cat > /root/soar-secrets.env << 'EOF'
THEHIVE_API_KEY=CLE_API_THEHIVE_ICI
ABUSEIPDB_API_KEY=CLE_API_ABUSEIPDB_ICI
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/TON_WEBHOOK
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=wazuh-wui
EOF

chmod 600 /root/soar-secrets.env
gpg --symmetric --cipher-algo AES256 /root/soar-secrets.env
shred -u /root/soar-secrets.env
```

---

## 18.3 L3-3 — Playbook de fermeture de case

Script `check_cases.sh` tournant en cron toutes les heures :
- Liste les cases TheHive ouverts depuis > 24h
- Re-vérifie l'IP via AbuseIPDB
- Si score < 10 → ferme le case (status Resolved, FalsePositive)
- Sinon → laisse ouvert

```bash
crontab -e
# Ajouter :
0 * * * * /root/check_cases.sh >> /var/log/soar-case-cleanup.log 2>&1
```

---

## 18.4 L3-4 — Script de démonstration soar-demo.sh

```bash
# Usage
/root/soar-demo.sh all    # Démonstration complète (soutenance)
/root/soar-demo.sh ssh    # Use case #1 uniquement
/root/soar-demo.sh scan   # Use case #2 uniquement
/root/soar-demo.sh dns    # Use case #3 uniquement
```

Le script injecte des logs dans `auth.log` et envoie des webhooks curl directement à Shuffle pour simuler les trois scénarios d'attaque sans infrastructure supplémentaire.

### Checklist Niveau 3

```
[✅] L3-1 : Use case #3 Exfiltration DNS
            Règle Suricata sid:9000002 + Wazuh 100003
            Workflow dns-exfil-triage — TheHive + AbuseIPDB + Discord
            Test curl → case TheHive severity H, TLP:RED, T1048.003/TA0010
[ ]  L3-2 : Gestion des secrets — .env GPG + Docker secrets
[ ]  L3-3 : Playbook fermeture de case — cron + API TheHive
[ ]  L3-4 : Script soar-demo.sh — 3 use cases en une commande
```

---

## Références

| Ressource | URL |
|-----------|-----|
| Documentation TheHive 4 (GitHub) | https://github.com/TheHive-Project/TheHiveDocs/tree/master/TheHive4 |
| Documentation Cortex | https://github.com/TheHive-Project/CortexDocs |
| Documentation Shuffle | https://shuffler.io/docs |
| API TheHive 4 | https://github.com/TheHive-Project/TheHiveDocs/blob/master/TheHive4/API/README.md |
| API Wazuh | https://documentation.wazuh.com/current/user-manual/api/reference.html |
| MITRE ATT&CK — T1110 | https://attack.mitre.org/techniques/T1110/ |
| MITRE ATT&CK — T1046 | https://attack.mitre.org/techniques/T1046/ |
| MITRE ATT&CK — T1048 | https://attack.mitre.org/techniques/T1048/ |
| AbuseIPDB API v2 | https://docs.abuseipdb.com/#check-endpoint |
| Emerging Threats — Suricata rules | https://rules.emergingthreats.net/ |
