# SayNoMore

![c4b311a6-165e-437a-b2af-3d02f8bf007f](https://github.com/user-attachments/assets/7d2c6928-2344-41e8-ab6a-c9ae7ce6c8a3)

SayNoMore è un semplice servizio One Time Secret per condividere password o informazioni sensibili visualizzabili una sola volta. 

## 🔐 Caratteristiche

- ✉️ Segreti leggibili solo una volta
- 🧼 Distruzione automatica dopo la lettura (con sovrascrittura a zeri)
- 🔒 Cifratura AES-256-CBC
- 🧠 Zero knowledge: la chiave di decrittazione non viene mai salvata
- 💻 Nessun database richiesto, solo file system

## 🚀 Come funziona

1. Inserisci un messaggio nel form
2. Ottieni un link contenente token + chiave
3. Invia il link a chi vuoi
4. Il segreto si autodistrugge dopo l’apertura

## 🛠️ Requisiti

- PHP 7.4+
- Estensione OpenSSL abilitata
- Server web con permessi di scrittura nella cartella `/data`

## 🔗 Demo

https://saynomore.muninn.ovh

# Screenshot

Scrivi il suo segreto e genera il link
![immagine](https://github.com/user-attachments/assets/ac9ade19-cf87-4a12-8fd7-d7ac01d89e5d)

Copia il link con il pulsante Copy, o a mano se preferisci
![immagine](https://github.com/user-attachments/assets/e3e0670c-333e-400b-a7cb-7faf429c74cb)

Invia il link al destinatario, una volta aperto lo vedrà in questo modo
![immagine](https://github.com/user-attachments/assets/0119ef77-1b1b-45ef-b4b6-591c4b65d502)

