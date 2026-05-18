# MarlinSpike

Version actuelle : `3.5.5`

Langues : [English](README.md) · **Français**

MarlinSpike est une plateforme d'analyse réseau OT/ICS passive conçue depuis zéro, dans la tradition de la cartographie de topologie type GrassMarlin, mais habillée d'un atelier web multi-utilisateurs pensé pour de vraies missions de terrain. Elle analyse les captures PCAP et PCAPNG, construit un graphe de topologie, infère les niveaux Purdue, identifie les fournisseurs et fait remonter des indicateurs de risque exploitables par un intervenant — communications inter-zones, services en clair, balises de type C2, communications externes suspectes, exfiltration DNS — puis exporte le tout sous forme d'artefacts JSON portables qui circulent avec l'équipe.

![MarlinSpike Hero](docs/screenshots/00-hero.png)

**Conçu pour les missions d'équipe sur site** — multi-utilisateurs, parcours sans JS pour les flux principaux, cible `1 cœur / 1 Go RAM`, et artefacts JSON portables.

**Atelier bilingue** (English / Français) — chaque écran bascule entre les langues, y compris les catégories de constats, descriptions et recommandations émises par le moteur.

**2,45 M paquets (1,7 Go) -> 2 449 nœuds, 2 662 arêtes, 75 constats en 58 secondes.**

Dépôt : [github.com/eris-ot/marlinspike](https://github.com/eris-ot/marlinspike)

## Ce qu'est MarlinSpike

MarlinSpike n'est pas qu'un visualiseur de topologie ni qu'un parseur de paquets.

C'est une plateforme d'analyse déployable sur le terrain, construite autour de quatre idées :

- L'analyse OT/ICS passive d'abord : on entre des fichiers de capture, aucun paquet n'est renvoyé sur le réseau.
- Un remplacement de fond pour GrassMarlin : reconstruction de topologie moderne, classification orientée protocole, et reporting adapté à l'analyste, sans hériter du vieux modèle desktop mono-utilisateur.
- Un atelier multi-utilisateurs : projets, dépôts, rapports, historique, administration, et une URL partagée pour toute l'équipe d'engagement.
- Un contrat de rapport portable : le moteur peut tourner en mode headless, produire des artefacts de rapport, et ces artefacts peuvent être consultés dans l'atelier intégré ou consommés ailleurs.

Le résultat est un modèle d'exploitation différent de celui d'un analyseur desktop. MarlinSpike est fait pour être déposé sur un hôte d'engagement temporaire, alimenté par des captures issues de TAPs, de ports SPAN ou d'une collecte externe, et utilisé en collaboration pendant le triage et l'évaluation.

## Principes de conception

MarlinSpike est construit autour de quelques contraintes pratiques :

- Le moteur reste autonome et peut produire des artefacts de rapport en mode headless.
- L'artefact de rapport est la frontière de passage entre l'analyse de paquets et la revue en aval.
- Le flux principal est `projet -> scan -> rapport -> atelier -> actions de triage`.
- Les flux web principaux restent utilisables sans JavaScript côté client.
- La base de code reste volontairement extensible pour les intervenants OT/ICS qui travaillent sur le terrain, pas seulement pour les développeurs système.

Les fonctionnalités interactives du navigateur peuvent améliorer la vitesse et le confort, mais l'expérience de triage principale doit rester accessible directement depuis du HTML rendu.

## Points forts

- Analyse passive uniquement : aucun balayage actif, aucune transmission de paquets
- Décodage des protocoles OT pour Modbus, EtherNet/IP, S7, DNP3, PROFINET, OPC UA, BACnet, et plus
- Substrat DPI Rust étendu via `marlinspike-dpi` : 34 dissecteurs de protocoles, sortie d'événements Bronze v2, inspection de l'intégrité des trames, analyse d'anomalies ICMP, et analyse stateful d'anomalies L2 ; les événements `parse_anomaly` de bilgepump sont désormais consommés et exposés sous forme de `l2_anomalies` dans l'artefact de rapport, et les observations ARP par paquet (`arp_observations`) sont collectées sur le chemin tshark pour les plugins d'analyse ARP en aval
- Construction de topologie avec inférence de niveau Purdue et identification de fournisseur
- Surface de risque pour l'exposition d'accès distant, les balises type C2, les canaux externes suspects, les anomalies d'entropie DNS, les violations de politique, une cartographie MITRE ATT&CK complète avec tactiques, sous-techniques, vues matricielles, recommandations de réponse, et conseils de remédiation alignés sur les exigences SR de l'IEC 62443
- Interface web Flask avec un atelier d'analyste multi-mode amélioré, gestion de projet, visualiseur de rapport, comparaison baseline/dérive, inventaire d'actifs, historique de scans, et un catalogue de couverture de détection `/capabilities` adossé aux sources
- Onglet Vue d'ensemble du projet (Project Overview) comme surface d'arrivée par défaut : parcourt chaque rapport d'un projet, déduplique les actifs (clé MAC, repli IP) et les constats (`(catégorie, sorted(affected_nodes), sorted(affected_edges))`) à travers les captures, promeut la sévérité au niveau le plus élevé observé, et restitue une bande de KPI agrégée, une barre de sévérité, un tableau de constats, un inventaire d'actifs, une liste de protocoles et un ensemble de pastilles de couverture ATT&CK — pur calcul, sans migration de schéma
- Déploiement Docker Compose avec PostgreSQL en backend
- Moteur DPI Rust via [`marlinspike-dpi`](https://github.com/eris-ot/marlinspike-dpi) activé par défaut (`--dpi-engine auto`), intégré à l'image depuis une référence GitHub épinglée — 14× plus rapide que le repli Python tshark sur les grosses captures
- Surfaces d'exécution MITRE ATT&CK fournies par le dépôt autonome [`marlinspike-mitre`](https://github.com/eris-ot/marlinspike-mitre) à une référence GitHub épinglée lors du build de l'image
- Exécution optionnelle d'IOC malware en Stage 4b alimentée par les dépôts autonomes `marlinspike-malware` et `marlinspike-malware-rules` quand leurs arguments de build sont fournis

## Démarrage rapide

1. Cloner le dépôt et entrer dans le répertoire du projet.

```bash
git clone https://github.com/eris-ot/marlinspike.git
cd marlinspike
```

2. Copier le fichier d'environnement d'exemple et définir des secrets robustes.

```bash
cp .env.example .env
```

3. Construire et démarrer la stack.

```bash
docker compose up -d --build
```

4. Ouvrir l'application sur `http://127.0.0.1:5001` ou via votre proxy inverse.

Au premier démarrage, MarlinSpike crée un utilisateur admin. Si `ADMIN_PASSWORD` est vide, un mot de passe aléatoire est généré et affiché dans les logs du conteneur.

Voir [INSTALL.md](INSTALL.md) pour un déroulé de déploiement générique.

## Documentation

Si vous cherchez la documentation principale du dépôt, commencez ici :

- Démarrage : [INSTALL.md](INSTALL.md)
- Famille de dépôts et structure de la suite : [docs/repo-family.md](docs/repo-family.md)
- Modèle de compatibilité : [COMPATIBILITY.md](COMPATIBILITY.md)
- Architecture et frontières d'extension : [docs/extensibility-contracts.md](docs/extensibility-contracts.md)
- Proposition de format de bundle de rapport zippé : [docs/msbundle-format.md](docs/msbundle-format.md)
- Guide ATT&CK pour utilisateur final : [docs/mitre-attack-guide.md](docs/mitre-attack-guide.md)
- Dépôt du plugin MITRE partagé : `marlinspike-mitre`
- Copie vendorée du runtime ATT&CK : [`plugins/marlinspike_mitre/`](plugins/marlinspike_mitre/) et [`rules/mitre/base.yaml`](rules/mitre/base.yaml)
- Helper de synchronisation MITRE bootstrap : [`scripts/sync-mitre-bootstrap.sh`](scripts/sync-mitre-bootstrap.sh)
- Helper de subtree de la suite : [`scripts/update-subtrees.sh`](scripts/update-subtrees.sh)
- Helper de synchronisation moteur bootstrap : [`scripts/sync-msengine-bootstrap.sh`](scripts/sync-msengine-bootstrap.sh)
- Workflow de contribution et de développement : [CONTRIBUTING.md](CONTRIBUTING.md)
- Historique des versions du moteur et du produit : [releases.md](releases.md)
- Historique des versions du visualiseur live et du streaming : [releases-live.md](releases-live.md)
- Direction produit de l'espace de travail analyste : [docs/analyst-workspace-roadmap.md](docs/analyst-workspace-roadmap.md)
- Corpus public de recherche d'empreintes : [docs/public-fingerprint-corpus.md](docs/public-fingerprint-corpus.md)
- Notes sur la bibliothèque d'échantillons : [presets/README.md](presets/README.md)

La terminologie clé d'extensibilité dans ce dépôt :

- Moteurs Rust : composants face aux paquets et fortement orientés événements, comme la DPI
- Plugins Python : analyse face au rapport, enrichissement et logique de triage
- Packs de règles YAML : mappings déclaratifs, suppressions et politique locale

La terminologie clé de la famille de dépôts :

- `marlinspike` : dépôt suite qui vendore certains dépôts de composants comme sous-dépôts par subtree et qui peut épingler des dépendances de build autonomes
- `marlinspike-msengine` : dépôt du moteur principal, package interne et nom de CLI `msengine`
- `marlinspike-workbench` : dépôt de l'interface web qui peut consulter des rapports avec ou sans appel au moteur local
- `marlinspike-mitre` : dépôt autonome partagé du plugin MITRE ATT&CK consommé comme dépendance de build épinglée pour les surfaces de plugin et de règles à l'exécution
- `marlinspike-dpi` : dépôt autonome partagé du moteur DPI Rust consommé comme dépendance de build épinglée dans l'image de l'application
- `marlinspike-malware` : dépôt autonome partagé du moteur Rust IOC consommé comme dépendance de build optionnelle épinglée dans l'image de l'application
- `marlinspike-malware-rules` : dépôt autonome partagé de contenu de règles consommé comme dépendance de build optionnelle épinglée pour les packs IOC publiés, manifestes, et artefacts de bundle compilés

Les dépôts de composants sont prévus pour être les sources de vérité. Le dépôt suite existe pour épingler et vendorer une combinaison connue pour fonctionner, à destination des équipes qui veulent un seul clone avec toutes les pièces à jour.
Le préfixe initial de subtree `msengine/` existe désormais sous forme bootstrap. Tant que l'extraction complète n'est pas terminée, `_ms_engine.py` à la racine reste la source opérationnelle du moteur, et [`scripts/sync-msengine-bootstrap.sh`](scripts/sync-msengine-bootstrap.sh) en miroite le contenu vers la copie subtree.
Le build Docker actuel épingle `marlinspike-dpi` à `326bdbb744a7b8f71295381fd209d9587dc09a3b` (version v1.7.0) par défaut via `MARLINSPIKE_DPI_REF`, `marlinspike-mitre` à `c3583ec2d189b8cde69f2160da6a5e8e5b643f7b` via `MARLINSPIKE_MITRE_REF`, `marlinspike-malware` à `02eb369c32e5050796c76be500c009dc0cb8940d` via `MARLINSPIKE_MALWARE_REF`, et `marlinspike-malware-rules` à `99cbe9358d0a5047d9b5e57a7e4ff5eafdee9bd4` via `MARLINSPIKE_MALWARE_RULES_REF`. Le 28 mars 2026, la référence des règles a été rafraîchie vers un commit publié valide, et le dépôt malware a été confirmé lisible publiquement à la référence épinglée. Surchargez ces arguments de build dans votre environnement si vous avez besoin d'une autre combinaison connue. L'application préfère la surface `packs/` publiée au lieu de la copie dev/test du dépôt moteur lors de la découverte des règles.

## Démonstration ATT&CK

MarlinSpike inclut désormais une implémentation ATT&CK complète dans le flux de rapport,
avec les métadonnées de version ATT&CK, les vues matricielles groupées par tactique, les sous-techniques,
les mesures d'atténuation et les recommandations de réponse.

Voir le guide utilisateur ici :

- [docs/mitre-attack-guide.md](docs/mitre-attack-guide.md)

Le guide inclut des captures d'écran et explique comment naviguer entre constats,
mappings ATT&CK, actifs et topologie pendant le triage.

## Positionnement : atelier d'analyste vs outil desktop

MarlinSpike n'est pas un analyseur desktop généraliste. Il est conçu spécifiquement comme un atelier d'analyste temporaire pour les engagements et évaluations de sécurité OT.

| Aspect | MarlinSpike (ce projet) | Outils desktop type GRASSMARLIN |
|------|------|------|
| **Cas d'usage principal** | Démarrage sur un IPC ou un portable de terrain pendant un engagement en usine, revue des PCAPs collectés par l'équipe, et restitution d'artefacts d'évaluation portables | Analyse approfondie en solo sur un poste unique |
| **Modèle utilisateur** | Multi-utilisateurs, flux scopé par projet, avec authentification, contrôles admin et historique d'audit | Généralement mono-utilisateur d'abord |
| **Déploiement** | Application web Docker Compose légère, parcours sans JS pour les flux principaux, cible `1 cœur / 1 Go RAM` | Application GUI desktop avec des attentes de runtime côté client plus lourdes |
| **Flux de rapport** | PCAP de n'importe où vers des artefacts JSON auto-suffisants, consultables ici ou ailleurs, plus exports PDF/PNG/CSV | Flux centré sur l'outil avec un couplage plus fort à l'application locale |
| **Modèle opérationnel** | URL partagée pour l'équipe d'engagement, mise en place et démontage rapides, adapté à un usage temporaire ou en environnement isolé | Environnement desktop d'analyste persistant |
| **Extensibilité** | Pipeline d'analyse Python et templates HTML accessibles à la plupart des équipes sécurité | Souvent centré sur des stacks desktop compilées avec un chemin de personnalisation plus raide |

En résumé :
Posez MarlinSpike sur un hôte d'engagement temporaire ou isolé, donnez l'URL à l'équipe, alimentez-le avec les captures que vous avez collectées, exportez des rapports JSON portables propres, et démontez-le quand le travail est fini.

Si vous cherchez une application desktop mono-utilisateur permanente avec un autre périmètre, MarlinSpike n'essaie pas d'être cet outil, et c'est volontaire.

## Parité fonctionnelle avec GrassMarlin

MarlinSpike est conçu pour remplacer le flux principal de cartographie passive pour lequel les gens utilisaient historiquement GrassMarlin, en changeant l'enveloppe — d'une application desktop mono-utilisateur à un atelier web partagé.

| Capacité | État de MarlinSpike | Notes |
|------|------|------|
| Analyse PCAP passive | Oui | Accepte `pcap` et `pcapng` depuis l'interface web ou le moteur autonome |
| Cartographie de topologie consciente de l'OT | Oui | Carte de relations, graphe nœuds/arêtes, indices de fournisseur et inférence Purdue |
| Inventaire d'actifs | Oui | Rôles par actif, services, protocoles et contexte côté intervenant |
| Analyse OT consciente du protocole | Oui | Modbus, EtherNet/IP, S7, DNP3, PROFINET, OPC UA, BACnet, IEC 104, LLDP/CDP/STP/LACP, et plus |
| Surface de risque depuis le trafic passif | Oui | Ingénierie en clair, chemins en écriture, communications externes suspectes, balises, exfiltration DNS et violations Purdue |
| Sorties exportables | Oui | Artefacts JSON portables, plus chemins d'export PDF/PNG/CSV depuis l'interface |
| Flux d'analyste en équipe | Dépasse | Collaboration scopée par projet, accès URL partagé, historique, revue baseline/dérive et contrôles admin sont natifs au lieu d'être rajoutés |
| Contrat d'analyse headless | Dépasse | Le moteur peut tourner indépendamment, émettre des artefacts portables, et être revu plus tard dans l'atelier ou ailleurs |
| Client desktop lourd | Différent par design | Remplacé par un atelier dans le navigateur et des parcours sans JS pour un déploiement de terrain temporaire et partagé |

### En amélioration active

- Profondeur d'empreinte et confiance de classification sur plus de fournisseurs et familles d'équipements
- Parcours de drill-down rendus côté serveur dans le visualiseur
- Usage plus riche des observations protocoles Bronze et des artefacts extraits dans l'interface de rapport
- Enrichissement protocole-natif au-delà du contrat de rapport actuel

### Limites assumées

- MarlinSpike est un **outil d'analyse PCAP**, pas une plateforme de monitoring continu. Capturez avec votre propre outillage (Wireshark, tshark, un TAP, un port SPAN) et apportez le PCAP dans MarlinSpike pour l'analyse. Pour la capture live continue, la collecte multi-capteurs et le monitoring OT centralisé, voir [FATHOM](https://github.com/eris-ot).
- MarlinSpike n'est pas un scanner actif.
- MarlinSpike n'est pas un client desktop lourd permanent.
- Le moteur DPI Rust autonome est un substrat de dissection, pas le produit complet.
- Une partie de la couverture protocole et du scoring de plus haut niveau vit toujours dans la couche d'analyse Python aujourd'hui, par design.

## Architecture du moteur

MarlinSpike garde la dissection de paquets séparée du flux d'analyste.

### Stack d'analyse actuelle

- Stage 1 : ingestion et validation de la capture
- Stage 2 : dissection de protocole
- Stage 3 : construction de topologie, inférence Purdue et identification d'empreintes
- Stage 4 : triage de compromission et surface de risque
- Sortie : artefact JSON portable consommé par l'atelier web

### Options de moteur DPI

MarlinSpike peut actuellement exécuter le Stage 2 de deux façons :

- Dissection Python/tshark intégrée via `_ms_engine.py`
- Dissection Rust externe via [`marlinspike-dpi`](https://github.com/eris-ot/marlinspike-dpi)

Le chemin Rust est volontairement scopé comme un moteur DPI autonome. MarlinSpike peut l'appeler comme un parseur Stage 2 externe, adapter sa sortie Bronze vers le pipeline de rapport actuel, et continuer à utiliser les couches existantes de topologie, triage et reporting. Cela garde le parseur de paquets réutilisable sans forcer le produit analyste à se réduire au parseur.

### Ce que `marlinspike-dpi` représente aujourd'hui

- C'est un moteur DPI Rust autonome avec des surfaces CLI, bibliothèque et FFI.
- Il accepte les captures `pcap` et `pcapng` classiques.
- Il livre actuellement 34 dissecteurs de protocoles couvrant le trafic OT/ICS, IT et L2.
- Il émet des événements Bronze v2 que MarlinSpike peut consommer dans cinq familles : transactions de protocole, observations d'actifs, observations de topologie, anomalies de parsing et artefacts extraits.
- Il superpose une inspection adjacente au parsing via les vérifications d'intégrité de trame `stovetop`, l'analyse d'anomalies ICMP `icmpeeker` et le suivi stateful d'anomalies L2 `bilgepump`.
- Il remplace l'étape de dissection, pas la logique de triage de compromission de plus haut niveau.

C'est délibéré. La valeur de MarlinSpike n'est pas seulement le décodage rapide des paquets. Sa valeur est de transformer du trafic OT passif en topologie, en constats et en décisions d'intervenant que l'équipe peut réellement utiliser.

### Modèle d'extensibilité

MarlinSpike utilise trois surfaces d'extension à dessein :

- Moteurs Rust : composants face aux paquets ou fortement orientés événements, là où le débit, la sûreté mémoire et la réutilisation de parseur comptent le plus. Aujourd'hui cela signifie principalement des moteurs de type DPI comme [`marlinspike-dpi`](https://github.com/eris-ot/marlinspike-dpi).
- Plugins Python : analyse face au rapport, enrichissement, logique de triage et post-traitement qui opèrent sur l'artefact JSON portable de MarlinSpike plutôt que sur les paquets bruts.
- Packs de règles YAML : mappings déclaratifs, contrôles d'activation, surcharges par site et autre contenu de politique utilisé par les plugins, sans transformer la configuration en un nouveau langage de programmation.

En résumé :

- Rust trouve des faits dans le trafic brut.
- Python transforme ces faits en jugements côté intervenant.
- YAML déclare les mappings et la politique locale.

Cette séparation est volontaire. MarlinSpike n'est pas écrit en « Rust pour tout » parce que l'application principale doit rester facile à étendre par la communauté OT/ICS au sens large, y compris les intervenants, les défenseurs et les consultants qui peuvent avoir besoin d'ajuster la logique pendant un incident actif. Rust excelle pour des moteurs de paquets sûrs en mémoire et réutilisables. Python reste plus adapté à l'itération rapide, à l'extension spécifique au site et à la logique de rapport adaptée au terrain quand une équipe triage activement un environnement.

Exemple actuellement livré :

- `marlinspike-mitre` : dépôt sœur faisant autorité à `marlinspike-mitre` ; l'image de l'application superpose maintenant les surfaces de plugin et de règles à l'exécution depuis le dépôt autonome épinglé vers [`plugins/marlinspike_mitre/`](plugins/marlinspike_mitre/) et [`rules/mitre/base.yaml`](rules/mitre/base.yaml) au moment du build. Les scans réussis peuvent émettre un artefact sidecar `-mitre.json`, et le visualiseur de l'atelier peut le charger depuis la surface `extensions` du rapport.
  Le runtime actuel expose les métadonnées et le versioning ATT&CK complets, les tactiques, les sous-techniques, les groupements de tactiques prêts pour la matrice, les mesures d'atténuation, les URLs ATT&CK et des recommandations de réponse riches dans le visualiseur.
  Les notes d'interprétation côté utilisateur vivent dans [docs/mitre-attack-guide.md](docs/mitre-attack-guide.md).
- `marlinspike-malware` : dépôt sœur faisant autorité à `marlinspike-malware`, avec `_ms_engine.py` qui l'invoque comme moteur Stage 4b optionnel. Quand `MARLINSPIKE_MALWARE_REPO` et `MARLINSPIKE_MALWARE_REF` sont fournis pendant le build de l'image, le binaire d'exécution est superposé dans `/opt/marlinspike-malware/bin/`.
- `marlinspike-malware-rules` : dépôt sœur faisant autorité à `marlinspike-malware-rules`, hébergeant le contenu publié `packs/`, `manifests/index.yaml` et les artefacts de bundle compilés. La surface publiée actuelle est de 30 packs et 921 règles. Quand `MARLINSPIKE_MALWARE_RULES_REPO` et `MARLINSPIKE_MALWARE_RULES_REF` sont fournis pendant le build de l'image, ces ressources sont superposées dans `/usr/share/marlinspike-malware/rules/`, et le moteur pointe vers `/usr/share/marlinspike-malware/rules/packs`.

Voir [`docs/extensibility-contracts.md`](docs/extensibility-contracts.md) pour les frontières de contrat concrètes des moteurs Rust, plugins Python et packs de règles YAML.

Si vous décidez où une nouvelle pièce doit aller, voici la règle de pouce :

- Si elle consomme du `pcap` brut, des flux de paquets ou des événements de protocole en grand volume, elle appartient probablement à un moteur Rust.
- Si elle consomme l'artefact de rapport MarlinSpike fini, elle appartient probablement à un plugin Python.
- Si les analystes doivent pouvoir l'ajuster sans modification de code, elle appartient probablement à un pack de règles YAML.

## Couverture de détection et de standards

L'histoire publique actuelle de détection et de standards de MarlinSpike est volontairement bornée à ce que le moteur émet déjà aujourd'hui.

- L'implémentation MITRE ATT&CK complète est désormais présente via le runtime partagé `marlinspike-mitre`, avec métadonnées de version ATT&CK, sortie matricielle consciente des tactiques, sous-techniques, contexte de technique parente, mesures d'atténuation et recommandations de réponse
- `marlinspike-dpi` contribue désormais une surface d'observables passifs plus large : 34 dissecteurs de protocoles, familles d'événements Bronze v2 et flux d'anomalies adjacentes au parser depuis `stovetop`, `icmpeeker` et `bilgepump`
- L'inférence du modèle Purdue et les vérifications de communications inter-niveaux font partie du flux de triage principal
- Les recommandations de remédiation du Stage 4 sont alignées sur les exigences SR de l'IEC 62443 pour les classes de constats actuellement produites par le moteur
- Les instances déployées publient un catalogue de couverture de détection intégré à `/capabilities`, explicitement présenté comme ce que MarlinSpike peut détecter, pas ce qu'il a déjà détecté dans un environnement donné
- La page `/capabilities` regroupe maintenant les classes de constats actuelles du rapport, la couverture parser de `marlinspike-dpi`, la couverture d'observables et de règles de `marlinspike-malware` et l'ensemble actuel de mappings ATT&CK derrière des contrôles filtrables (source, type, famille, sévérité, recherche)
- La section actuelle `marlinspike-malware` reflète la surface de contenu publiée par `marlinspike-malware-rules`, désormais à 30 packs et 921 règles, et la section ATT&CK reflète l'implémentation ATT&CK complète vendorée livrée par `marlinspike-mitre`

C'est désormais positionné comme une implémentation ATT&CK complète pour le flux orienté rapport de MarlinSpike. Le périmètre reste volontairement borné aux preuves issues de trafic passif et au triage analyste, plutôt qu'à un crosswalk de conformité plus large ou à toutes les analytics ATT&CK possibles.

## Vue d'ensemble des fonctionnalités

MarlinSpike transforme des captures de paquets brutes en un flux qu'un opérateur OT, un propriétaire d'actifs ou un intervenant peut réellement utiliser.

### Analyse

- Analyse PCAP et PCAPNG passive avec dissection de protocole consciente de l'OT
- Carte de relations et reconstruction de topologie avec inférence Purdue
- Triage piloté par le rapport avec constats de risque, indicateurs C2 et contexte d'actifs
- Inventaire d'actifs détaillé, exposition de services, analyse de conversations et reporting de table MAC

### Flux de travail

- Exécution de scan ad hoc depuis l'interface web
- Gestion multi-captures, y compris traitement de gros PCAPs avec progression en streaming
- Organisation scopée par projet pour les captures et les rapports
- Onglet Project Overview comme surface d'arrivée par défaut du projet — agrégation cross-rapport sur chaque capture du projet (déduplication d'actifs, déduplication de constats avec promotion de sévérité, agrégation de protocoles, couverture ATT&CK)
- Historique de rapports, support du retry et revue baseline-vs-dérive entre artefacts
- Artefacts JSON portables consultables dans MarlinSpike ou ailleurs

### Administration

- Accès multi-utilisateurs avec contrôles admin
- Historique de scans et piste d'audit
- Vues de santé système et de monitoring
- Gestion de la bibliothèque d'échantillons

## Support d'export

Le flux de rapport supporte l'export directement depuis l'interface :

- Imprimer ou enregistrer en PDF depuis le visualiseur de rapport
- Export PNG depuis le visualiseur de topologie
- Export CSV depuis la vue d'inventaire d'actifs

## Project Overview — agrégation cross-rapport

La plupart des engagements produisent plus d'une capture. Un site peut être capturé chaque jour pendant une semaine, ou différents switches peuvent être tappés le même jour, ou la même PCAP peut être rejouée après un changement de règles. MarlinSpike exposait auparavant tout ça comme des artefacts de rapport séparés côte à côte ; l'analyste devait les recoller mentalement.

L'onglet Project Overview fait ce recollage pour vous et c'est la surface par défaut quand vous ouvrez un projet.

Ce qu'il fait :

- Parcourt chaque rapport du projet (rapports moteur plus tout sidecar de plugin remonté via le pont d'extensions existant — APT, ARP, MITRE).
- Déduplique les actifs par MAC d'abord et par IP ensuite. Chaque enregistrement d'actif porte `first_seen_report` / `last_seen_report` et un `report_count`.
- Déduplique les constats par `(catégorie, sorted(affected_nodes), sorted(affected_edges))`. La sévérité est promue à la plus haute observée à travers les rapports ; le rapport le plus récent gagne pour le texte de description. Chaque constat affiche son nombre d'occurrences sous forme de `vu dans N rapports sur M`.
- Agrège les protocoles et la couverture des techniques ATT&CK à travers les rapports.
- Restitue une bande de KPI, une barre de distribution de sévérité, un tableau de constats trié par sévérité puis par nombre d'occurrences, un inventaire d'actifs avec une barre de filtre collante, un ensemble de pastilles de distribution de protocoles, et un ensemble de pastilles de couverture ATT&CK.

Ce qu'il n'est pas :

- Pas une migration de base de données. L'agrégation est du pur calcul sur les artefacts JSON de rapport sur disque, et tourne à chaque ouverture de l'onglet. Pas de changement de schéma, pas de stockage supplémentaire, pas de tâche de fond.
- Pas un remplacement du visualiseur par rapport. La matrice MITRE par rapport, les pivots de preuves, la baseline/dérive et les chemins d'export au niveau rapport vivent toujours sur le rapport lui-même. Utilisez Overview pour « à quoi ressemble cet engagement globalement », et utilisez un rapport spécifique pour « que s'est-il passé dans cette capture ».

L'API d'agrégation est exposée sur `/api/projects/<id>/aggregate` pour les outils qui veulent consommer la même agrégation sans rendre l'onglet. D'après les notes de version de la v2.4.0, l'agrégateur est testé unitairement sur la déduplication par rapport, la déduplication cross-rapport, la promotion de sévérité, les clés de repli IP, l'agrégation ATT&CK, la ventilation par profil de scan et l'isolation des échecs de chargement ; un smoke test Playwright couvre le chemin complet login → sélection projet → rendu Overview → KPI / barre de sévérité / tri des constats / filtre d'actifs / cyclage d'onglets.

## Capacités additionnelles

- Revue baseline et dérive avec comparaison de topologie ajoutée, supprimée, modifiée et inchangée
- Visualisation de topologie en direct pendant les scans actifs
- Streaming de progression d'étape de scan avec visibilité sur les états ingest, analyze, classify et report
- Contrôles d'administration par utilisateur, dont les réinitialisations de mot de passe et les limites d'upload
- Actions de cycle de vie multi-rapports : voir, télécharger, supprimer et comparer
- Retry des scans échoués ou interrompus depuis l'historique de scans
- Administration de la bibliothèque d'échantillons avec gestion de catégories et contrôles d'upload/suppression de PCAP
- Saisie de filtre de capture et contrôles de suppression de ports éphémères dans le flux de scan
- Reporting de table MAC à côté de la vue d'évaluation principale

## Captures d'écran

Cliquer sur une vignette pour la version pleine taille.

### Project Overview (agrégation cross-rapport)

L'onglet Project Overview est la surface d'arrivée par défaut du projet. Il agrège chaque rapport du projet en une seule vue : KPIs, distribution de sévérité, constats dédupliqués triés par sévérité puis par nombre d'occurrences, et un inventaire d'actifs avec une barre de filtre collante. La barre de sévérité montre la distribution d'un coup d'œil avec des compteurs en ligne, et le tableau de constats suit dans combien de rapports du projet chaque constat distinct est apparu (colonne `SEEN IN`). Les enregistrements d'actifs et de constats sont par défaut clés MAC avec un repli IP, et portent l'attribution première/dernière apparition dans un rapport.

Cette capture a été prise sur le projet de benchmark 4SICS après avoir exécuté trois jours de captures `4SICS-GeekLounge` (`151020`, `151021`, `151022`) et un re-run du jour `151022`, soit quatre rapports au total. L'agrégateur a dédupliqué 119 occurrences de constats vers 96 constats distincts et 48 actifs uniques à travers les quatre captures.

<table>
  <tr>
    <td width="100%">
      <a href="docs/screenshots/28-project-overview-multiday.png">
        <img src="docs/screenshots/28-project-overview-multiday-fold.png" alt="Onglet Project Overview avec 4 rapports agrégés — bande de KPI, barre de sévérité, constats dédupliqués, inventaire d'actifs" width="100%">
      </a>
      <br>
      <sub>Project Overview après agrégation de quatre rapports 4SICS — 4 rapports, 48 actifs uniques, 96 constats distincts, 15 protocoles, 2 techniques ATT&CK mappées. Le tableau de constats affiche les nombres d'occurrences sous forme de `vu dans N sur M` et est trié par sévérité puis par occurrences.</sub>
    </td>
  </tr>
</table>

### Validation de flux en direct

Ces captures viennent d'un smoke test live de bout en bout pris le 28 mars 2026 contre le déploiement hébergé courant après l'exécution de trois PCAPs presets : `Modbus.pcap`, `S7comm.pcap` et le benchmark 4SICS en mode `fast`. Elles montrent le chemin principal de l'intervenant : `projet -> scan -> rapport -> atelier -> actifs`.

<table>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/22-live-dashboard.png">
        <img src="docs/screenshots/22-live-dashboard.png" alt="Tableau de bord live après validation smoke de déploiement" width="100%">
      </a>
      <br>
      <sub>Tableau de bord avec l'espace de scan mis en avant comme point de départ opérationnel.</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/23-live-projects.png">
        <img src="docs/screenshots/23-live-projects.png" alt="Espace de projet live utilisé pendant la validation smoke" width="100%">
      </a>
      <br>
      <sub>Espace scopé par projet montrant le conteneur d'engagement utilisé pour isoler les sorties du smoke.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/24-live-scans.png">
        <img src="docs/screenshots/24-live-scans.png" alt="Historique de scans live avec runs smoke terminés" width="100%">
      </a>
      <br>
      <sub>Historique de scans avec plusieurs runs terminés, dont le chemin de benchmark gros PCAP.</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/25-live-benchmark-viewer.png">
        <img src="docs/screenshots/25-live-benchmark-viewer.png" alt="Rapport de benchmark live dans l'atelier opérateur" width="100%">
      </a>
      <br>
      <sub>L'enveloppe opérateur sur le rapport de benchmark 4SICS avec cibles prioritaires, lacunes d'authentification et chemins en écriture en vue.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/26-live-modbus-viewer.png">
        <img src="docs/screenshots/26-live-modbus-viewer.png" alt="Rapport Modbus live dans l'atelier opérateur" width="100%">
      </a>
      <br>
      <sub>Une passe de validation plus petite spécifique au protocole, contre Modbus, montrant le même flux d'atelier sur une capture OT focalisée.</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/27-live-assets.png">
        <img src="docs/screenshots/27-live-assets.png" alt="Vue actifs live après validation smoke" width="100%">
      </a>
      <br>
      <sub>Le mode actifs transforme le rapport validé en un registre triable côté intervenant avec contexte d'équipement et preuves de risque.</sub>
    </td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/01-topology-viewer.png">
        <img src="docs/screenshots/01-topology-viewer.png" alt="Visualiseur de topologie" width="100%">
      </a>
      <br>
      <sub>Visualiseur de topologie et atelier d'analyste</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/02-report-viewer.png">
        <img src="docs/screenshots/02-report-viewer.png" alt="Constats d'évaluation et vue de rapport" width="100%">
      </a>
      <br>
      <sub>Constats d'évaluation et revue de rapport</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/03-asset-inventory.png">
        <img src="docs/screenshots/03-asset-inventory.png" alt="Inventaire d'actifs" width="100%">
      </a>
      <br>
      <sub>Inventaire d'actifs et contexte d'équipement</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/06-large-pcap-streaming.png">
        <img src="docs/screenshots/06-large-pcap-streaming.png" alt="Progression sur gros PCAP" width="100%">
      </a>
      <br>
      <sub>Exécution sur gros PCAP avec progression live</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/07-scan-history.png">
        <img src="docs/screenshots/07-scan-history.png" alt="Historique de scans" width="100%">
      </a>
      <br>
      <sub>Historique de scans et piste d'audit</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/08-projects.png">
        <img src="docs/screenshots/08-projects.png" alt="Espace projets" width="100%">
      </a>
      <br>
      <sub>Flux scopé par projet</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/09-users.png">
        <img src="docs/screenshots/09-users.png" alt="Administration des utilisateurs" width="100%">
      </a>
      <br>
      <sub>Administration multi-utilisateurs</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/11-diff-viewer.png">
        <img src="docs/screenshots/11-diff-viewer.png" alt="Visualiseur baseline et dérive" width="100%">
      </a>
      <br>
      <sub>Revue baseline et dérive</sub>
    </td>
  </tr>
</table>

### Atelier d'analyste amélioré

L'atelier d'analyste est désormais structuré comme une enveloppe opérateur complète plutôt que comme un visualiseur unique surchargé. Un rail de gauche persistant porte l'identité de l'atelier, le contexte de rapport, la navigation par mode et les utilitaires, pendant que la scène centrale et l'inspecteur de droite restent focalisés sur le travail de triage actif.

L'enveloppe actuelle supporte les surfaces `Dashboard`, `Map`, `Findings`, `Evidence`, `Assets`, `Intel`, `Risk` et `Reports` sans essayer de faire entrer chaque flux dans le canevas de topologie.

Cette capture vient d'un artefact de rapport validé en live après la mise à jour publique de `marlinspike-dpi` et montre l'enveloppe opérateur plus dense désormais utilisée par le visualiseur.

<table>
  <tr>
    <td width="100%">
      <a href="docs/screenshots/21-workbench-operator-shell.png">
        <img src="docs/screenshots/21-workbench-operator-shell.png" alt="Enveloppe opérateur avec navigation à gauche, bande de statut compacte et inspecteur persistant" width="100%">
      </a>
      <br>
      <sub>L'enveloppe opérateur utilise un rail de navigation pleine hauteur, une bande de statut compacte, une barre de commandes sur une ligne et un inspecteur persistant pour que la première vue reste focalisée sur le travail d'intervention.</sub>
    </td>
  </tr>
</table>

D'autres captures montrent en détail les surfaces de l'atelier basées sur les modes.

<table>
  <tr>
    <td width="33%">
      <a href="docs/screenshots/18-workbench-evidence-mode.png">
        <img src="docs/screenshots/18-workbench-evidence-mode.png" alt="Mode Evidence dans l'atelier d'analyste amélioré" width="100%">
      </a>
      <br>
      <sub>Le mode Evidence fait remonter les sessions enrichies, les indices d'identité, les pivots de chasse et les observables DPI préservés.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/19-workbench-findings-mode.png">
        <img src="docs/screenshots/19-workbench-findings-mode.png" alt="Mode Findings dans l'atelier d'analyste amélioré" width="100%">
      </a>
      <br>
      <sub>Le mode Findings donne aux intervenants une surface de triage dédiée plutôt que de tout entasser dans la carte.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/20-workbench-assets-mode.png">
        <img src="docs/screenshots/20-workbench-assets-mode.png" alt="Mode Assets dans l'atelier d'analyste amélioré" width="100%">
      </a>
      <br>
      <sub>Le mode Assets transforme l'atelier en un registre cherchable avec densité de preuves et contexte d'actifs.</sub>
    </td>
  </tr>
</table>

Les anciennes captures live restent utiles comme exemples de validation par protocole :

<table>
  <tr>
    <td width="33%">
      <a href="docs/screenshots/15-live-workbench-mqtt.png">
        <img src="docs/screenshots/15-live-workbench-mqtt.png" alt="Vue atelier d'analyste live MQTT" width="100%">
      </a>
      <br>
      <sub>Atelier MQTT live avec client, topic et enrichissement d'actifs préservés.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/16-live-workbench-radius.png">
        <img src="docs/screenshots/16-live-workbench-radius.png" alt="Vue atelier d'analyste live RADIUS" width="100%">
      </a>
      <br>
      <sub>Atelier RADIUS live avec métadonnées d'authentification, références d'objets et contexte de triage.</sub>
    </td>
    <td width="33%">
      <a href="docs/screenshots/17-live-workbench-ftp.png">
        <img src="docs/screenshots/17-live-workbench-ftp.png" alt="Vue atelier d'analyste live FTP" width="100%">
      </a>
      <br>
      <sub>Atelier FTP live après que le correctif public de panic du parser soit passé en production.</sub>
    </td>
  </tr>
</table>

## Configuration

Les principales variables d'environnement sont :

- `DB_PASSWORD` : mot de passe PostgreSQL
- `SECRET_KEY` : secret de session Flask
- `ADMIN_PASSWORD` : mot de passe admin initial
- `PCAP_MAX_SIZE` : taille d'upload maximale acceptée en octets (par défaut : 5 Go)
- `MARLINSPIKE_DPI_ENGINE` : sélection du moteur DPI — `auto` (par défaut, utilise Rust quand disponible), `marlinspike-dpi`, ou `python`
- `MARLINSPIKE_DPI_BIN` : chemin du binaire `marlinspike-dpi` (par défaut : auto-détecté depuis le PATH)

## Disposition des sources

Les modules canoniques de l'application sont :

- `_ms_engine.py`
- `_auth.py`
- `_models.py`
- `_config.py`
- `app.py`

Les modules sans préfixe underscore (`auth.py`, `models.py`, `config.py`) sont des shims de compatibilité pour que des outillages plus anciens puissent toujours les importer sans s'écarter de la vraie source.

## Données d'exemple

Le dépôt public n'embarque pas de corpus PCAP tiers. Si vous voulez une bibliothèque d'échantillons préréglée, ajoutez des captures sous `presets/<categorie>/` localement ou via l'interface admin après déploiement.

## Développement

- `python3 -m py_compile app.py _auth.py _config.py _models.py _ms_engine.py`
- `docker compose up --build`

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les directives de contribution, dont le travail en cours sur l'identification d'empreintes et l'enrichissement.

## Fathom

MarlinSpike est le cœur open source de **Fathom**, la plateforme commerciale de sécurité OT de [Erisforge Ltd.](https://github.com/eris-ot/marlinspike).

La plateforme commerciale Fathom ajoute des collecteurs distribués, de la hiérarchie, des diodes de données, le voyage forensique dans le temps et l'apprentissage de baseline à l'échelle entreprise. MarlinSpike est l'atelier open core léger que vous pouvez démarrer n'importe où.

Pour en savoir plus : [github.com/eris-ot/marlinspike](https://github.com/eris-ot/marlinspike).

## Remerciements

MarlinSpike est meilleur grâce aux personnes qui prennent le temps de le tester, de lire le code et d'ouvrir des issues ou des PRs. Contributeurs de la communauté :

- **[Michael Sargis (@MichaelMVS)](https://github.com/MichaelMVS)** — a attrapé une collision silencieuse dans le dictionnaire OUI `ICS_OUI_DB` qui faisait identifier à tort des équipements Honeywell comme étant GE dans chaque rapport ([PR #3](https://github.com/eris-ot/marlinspike/pull/3), v2.0.3)
- **Jerrid Brown** (OTPulse) — a fait passer de vraies captures de paquets DCS dans MarlinSpike et a remonté plusieurs problèmes de classification et d'UX qui ont conduit aux correctifs v2.0.1 / v2.0.2 (mauvaise classification multicast, mauvaise attribution OUI sur la MAC de gateway, bruit `NO_AUTH_OBSERVED`, fourre-tout « Application Server » du Niveau 3, heuristiques Purdue L3 vs L4)

Si vous trouvez un bug ou avez une empreinte à ajouter, [ouvrez une issue](https://github.com/eris-ot/marlinspike/issues) ou [envoyez une PR](https://github.com/eris-ot/marlinspike/pulls) — les contributeurs débutants sont très bienvenus.

## Licence

Ce dépôt est sous licence GNU Affero General Public License v3.0. Voir [LICENSE](LICENSE).

## Contact

Des questions ? Ouvrez un ticket sur [github.com/eris-ot/marlinspike/issues](https://github.com/eris-ot/marlinspike/issues).
