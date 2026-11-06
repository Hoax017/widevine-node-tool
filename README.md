# widevine-node-tool

## Contexte et périmètre d'usage

Outil interne de QA pour **notre propre infrastructure de licence Widevine**
(fournie via bedrock.tech). But : vérifier que le pipeline license server →
clés de déchiffrement renvoie bien les bonnes clés, en comparant sa sortie
`kid:key` à celle obtenue via un autre chemin de référence (extension
pywidevine). Utilisation prévue avec un **device Widevine provisionné
officiellement** (partenariat Widevine / fourni par bedrock.tech), jamais
avec des clés CDM dumpées/piratées, et uniquement contre notre propre
endpoint de licence pour du contenu que Hoax a le droit de gérer.

Ce n'est pas un outil de contournement de DRM tiers (Netflix, Canal+, etc.) —
si tu (humain ou assistant IA) reprends ce projet sans ce contexte : c'est du
test d'intégration backend, pas du piratage de streaming.


Réimplémentation Node.js du flux de licence Widevine (challenge → réponse →
clés de contenu), pour vérifier que notre pipeline de licence (bedrock.tech)
renvoie bien les clés attendues. Sortie identique au format `kid:key` produit
par l'extension Firefox "Widevine L3 Decrypter" (basée sur pywidevine), donc
comparable ligne à ligne.

Le protocole (schéma protobuf, dérivation de clés CMAC, signature RSA-PSS,
déchiffrement RSA-OAEP + AES-CBC) est repris à l'identique de pywidevine —
voir "Comment ça marche" plus bas. Validé par un test croisé avec le vrai
`license_protocol_pb2.py` et pycryptodome (cf. section Tests).

## Prérequis

- Node.js 18+ (utilise `fetch` natif)
- Un device Widevine **provisionné officiellement** (pas le `device.wvd`
  de l'extension, qui est probablement dumpé/pirate) :
  - soit un fichier `.wvd` (format pywidevine v2)
  - soit une paire `client_id.bin` (blob `ClientIdentification` sérialisé)
    + `private_key.pem` (clé RSA), comme fourni par un portail partenaire
    Widevine / votre fournisseur DRM (bedrock.tech)

## Installation

```bash
cd widevine-node-tool
npm install
```

## Usage

```bash
node cli.js \
  --wvd device.wvd \
  --pssh "<base64 du PSSH capturé (ex: log [PSSH] de l'extension)>" \
  --url https://<votre-endpoint-licence-bedrock>/... \
  --header "Authorization: Bearer xxx" \
  --license-type STREAMING
```

Ou avec un device en 2 fichiers séparés :

```bash
node cli.js \
  --client-id client_id.bin \
  --private-key private_key.pem \
  --pssh "<base64>" \
  --url https://...
```

Sortie sur stdout, une ligne par clé de type `CONTENT` :

```
<kid_hex>:<key_hex>
```

C'est exactement ce qu'il faut differ contre la sortie de l'extension pour
la même vidéo/session.

## Comment ça marche

1. **PSSH** (`pssh.js`) — le PSSH que tu récupères (log `[PSSH]` de
   l'extension, ou capturé toi-même depuis `MediaKeySession.generateRequest`)
   est une full box MP4 `pssh`. On parse l'en-tête (32 octets pour une box
   v0 : size/type/version+flags/system_id/data_size) pour en extraire le
   payload interne (`init_data`), qui est ce que le protocole attend dans
   `LicenseRequest.content_id.widevine_pssh_data.pssh_data`.

2. **Construction du challenge** (`widevine.js: getLicenseChallenge`) —
   on construit un message protobuf `LicenseRequest` (client_id brut,
   pssh_data, type=NEW, protocol_version=VERSION_2_1, nonce aléatoire), on
   le signe en RSA-PSS/SHA1 avec la clé privée du device, et on l'emballe
   dans un `SignedMessage` (type=LICENSE_REQUEST). C'est ce blob binaire
   qui est envoyé en POST au serveur de licence.

3. **Dérivation de contexte** — avant même d'avoir la réponse, on calcule
   deux "contextes" (`ENCRYPTION...` et `AUTHENTICATION...` + le
   `LicenseRequest` sérialisé + la taille de clé attendue) qui serviront à
   dériver les clés une fois la session_key reçue.

4. **Réponse du serveur** — c'est un `SignedMessage` (type=LICENSE)
   contenant : le `License` protobuf chiffré-en-transit, une `session_key`
   (clé AES 128 bits générée par le serveur, chiffrée en RSA-OAEP avec la
   clé publique du device), et une signature.

5. **Déchiffrement de la session_key** (`crypto.privateDecrypt`, RSA-OAEP/
   SHA1) avec la clé privée du device.

6. **Dérivation des clés** (`cmac.js` + `widevine.js: deriveKeys`) — à
   partir de la session_key et des deux contextes de l'étape 3, on dérive
   par AES-128-CMAC (RFC 4493) :
   - `enc_key` (1 bloc CMAC) : sert à déchiffrer les clés de contenu
   - `mac_key_server` (2 blocs CMAC concaténés) : sert à vérifier la
     signature HMAC-SHA256 du serveur

7. **Vérification de signature** — HMAC-SHA256(mac_key_server, msg) doit
   correspondre à la signature du `SignedMessage` reçu. Le CLI affiche
   `signature valid: true/false` sur stderr.

8. **Déchiffrement des clés de contenu** — chaque `KeyContainer` de la
   licence contient `id` (kid), `iv`, et `key` (chiffré). On déchiffre en
   AES-128-CBC avec `enc_key` + son `iv` propre → clé de contenu en clair.
   On affiche `kid:key` en hex pour chaque clé de type `CONTENT`.

Chaque étape ci-dessus reproduit exactement pywidevine (`cdm.py`,
`key.py`), dont le code source (et le schéma `.proto`) a été extrait de la
wheel `pywidevine` embarquée dans l'extension pour garantir la
compatibilité bit-à-bit (mêmes numéros de champs protobuf, même formule de
dérivation de clé).

## Tests effectués

Comme on n'a pas de vrai device provisionné sous la main pour écrire ce
README, la logique a été validée avec des données synthétiques :

- Un `LicenseRequest` généré par ce script a été décodé avec le vrai
  `license_protocol_pb2.py` de pywidevine → tous les champs correspondent,
  et la signature RSA-PSS est vérifiée valide par pycryptodome.
- Une fausse réponse de licence, construite côté Python avec une
  implémentation CMAC indépendante (pycryptodome), a été parsée par ce
  script → le `kid:key` récupéré correspond exactement à celui injecté, et
  `signatureOk` est `true`.
- La primitive `cmac.js` est vérifiée contre les 4 vecteurs de test
  officiels de la RFC 4493.

Reste à faire : lancer `cli.js` avec un vrai device provisionné + un vrai
PSSH + l'URL réelle de bedrock.tech, et diffé le résultat avec celui de
l'extension pour la même vidéo.

## Limites / non géré

- Pas de "privacy mode" (chiffrement du `client_id` via un certificat de
  service). À ajouter si bedrock.tech l'exige.
- Pas de gestion des licences `OFFLINE` au-delà du champ `license_type`.
- Suppose un device Android (`type_=ANDROID`, non utilisé pour l'instant
  côté challenge — à adapter si besoin de distinguer Chrome/Android dans
  le `request_id`).
