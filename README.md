# SayNoMore

![c4b311a6-165e-437a-b2af-3d02f8bf007f](https://github.com/user-attachments/assets/7d2c6928-2344-41e8-ab6a-c9ae7ce6c8a3)

SayNoMore è un semplice servizio One Time Secret per condividere password o informazioni sensibili visualizzabili una sola volta. 

## 🔐 Caratteristiche

- ✉️ Segreti leggibili solo una volta protetti da password (hash sha-512)
- 🧼 Distruzione automatica dopo la lettura (con sovrascrittura a zeri)
- 🔒 Cifratura AES-256-CBC
- 🧠 Zero knowledge: la chiave di decrittazione non viene mai salvata su server
- 💻 Nessun database richiesto, solo file system

## 🚀 Come funziona

1. Inserisci un messaggio e una password nel form
2. Ottieni un link contenente token + chiave
3. Invia il link a chi vuoi
4. Il segreto si autodistrugge dopo l’apertura o l'inserimento di una password errata

## 🛠️ Requisiti

- PHP 7.4+
- Estensione OpenSSL abilitata
- Server web con permessi di scrittura nella cartella `data`

## 🔗 Demo

https://saynomore.muninn.ovh

## ⚠ Attenzione

Tutto quello che pubblico esiste perchè serviva a me prima di tutto, non sono uno sviluppatore e potrebbero esserci bug anche critici.

Utilizzate quanto metto a disposizione senza garanzia alcuna

# Screenshot

Scrivi il suo segreto e genera il link
![immagine](https://github.com/user-attachments/assets/b967a27f-b716-4c09-ba2e-b09d71696cd0)

Copia il link con il pulsante Copy, o a mano se preferisci
![immagine](https://github.com/user-attachments/assets/e3e0670c-333e-400b-a7cb-7faf429c74cb)

Invia il link al destinatario, una volta aperto e inserita la password lo vedrà in questo modo
![immagine](https://github.com/user-attachments/assets/0119ef77-1b1b-45ef-b4b6-591c4b65d502)

