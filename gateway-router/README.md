# Gateway Router

Passerelle HTTP/HTTPS pilotée par SQLite pour héberger plusieurs applications sur une seule IP publique.

## Fonctionnement

- `GET /` affiche une page de sélection des applications.
- Chaque route est définie en base de données avec un préfixe public et une URL cible.
- Les requêtes vers `/conges/*` sont envoyées vers l'application congés correspondante.
- Les requêtes API sont redirigées automatiquement vers la bonne application grâce au cookie `gw_route` et au `Referer`.

## Installation

```bash
cd gateway-router
npm install
npm start
```

## Variables d'environnement

- `PORT` : port d'écoute de la passerelle, défaut `8080`
- `HTTPS_KEY_PATH` : chemin vers la clé privée TLS optionnelle
- `HTTPS_CERT_PATH` : chemin vers le certificat TLS optionnel

## Exemple de routes

Depuis `http://TON_IP/admin` :

- Nom: `Congés`
- Préfixe public: `/conges`
- Cible: `http://127.0.0.1:5001`
- Strip prefix: `Oui`

- Nom: `App 2`
- Préfixe public: `/app2`
- Cible: `http://127.0.0.1:5002`
- Strip prefix: `Oui`

## Notes importantes

- Si une application utilise des chemins absolus côté front, le routage par préfixe peut demander un ajustement.
- Pour ton application actuelle, les appels API relatifs ou le cookie `gw_route` permettent déjà de router correctement.
- Sur une IP brute, le HTTPS public avec certificat valide n'est généralement pas possible sans domaine. Tu peux utiliser HTTPS interne avec certificat auto-signé, ou rester en HTTP derrière la box.
