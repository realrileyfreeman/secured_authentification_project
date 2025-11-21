Project: Minimal Authentication System Reinforced with PBKDF2

Purpose. Provide a simple registration and login flow that stores only a salt and a PBKDF2-derived hash. No plaintext password storage.

Mechanics.
— Generate a 16-byte random salt via os.urandom.
— Derive the password using hashlib.pbkdf2_hmac with 100,000 iterations.
— Store data in an in-memory structure:

{
  "username": {
    "salt": "<hex>",
    "hash": "<hex>"
  }
}


— Verify by re-applying PBKDF2 with the stored salt.

Structure.
main.py: full logic (registration, login, hashing).
user_credentials: in-memory dictionary (no persistence).

Security notes.
— PBKDF2 slows down brute-force and dictionary attacks.
— Unique per-user salts neutralize precomputation and rainbow tables.
— No secret is stored in plaintext.
— Educational scope only: no persistence, no rate-limiting, no password policies.

Execution.

python main.py


Menu.
1 — register
2 — log in
3 — exit


Projet : Système d’authentification minimal renforcé par PBKDF2.

But. Fournir un flux d’inscription et de connexion stockant uniquement un sel et un hash dérivé via PBKDF2-HMAC-SHA256. Pas de stockage de mot de passe en clair.

Fonctionnement.
— Génération d’un sel aléatoire 16 octets via os.urandom.
— Dérivation du secret par hashlib.pbkdf2_hmac avec 100 000 itérations.
— Stockage dans une structure interne :

{
  "username": {
    "salt": "<hex>",
    "hash": "<hex>"
  }
}


— Vérification en réappliquant PBKDF2 avec le même sel.

Arborescence.
main.py : logique complète (enregistrement, connexion, hashing).
user_credentials : dictionnaire en mémoire (non persistant).

Points de sécurité.
— PBKDF2 itératif pour ralentir l’attaque par dictionnaire.
— Sels aléatoires uniques par utilisateur pour neutraliser pré-calculs et rainbow tables.
— Aucun secret stocké en clair.
— Code purement éducatif : absence de persistance, pas d’anti-bruteforce, pas de gestion de politique de mot de passe.

Exécution.

python main.py


Menu intégré.
1 — inscription.
2 — authentification.
3 — sortie.
