# SayNoMore

![c4b311a6-165e-437a-b2af-3d02f8bf007f](https://github.com/user-attachments/assets/7d2c6928-2344-41e8-ab6a-c9ae7ce6c8a3)

SayNoMore è un semplice servizio One Time Secret per condividere password o informazioni sensibili visualizzabili una sola volta.

## 🔐 Caratteristiche

- ✉️ Segreti leggibili solo una volta protetti da password (hashing Argon2id, salt automatico)
- 🔒 Cifratura AES-256-GCM con tag di autenticazione (rileva manomissioni del ciphertext)
- 🧠 Zero knowledge reale: la chiave di decrittazione viaggia nel fragment URL (`#`) e non viene mai inviata al server tramite il link
- ⏳ Scadenza configurabile dall'utente: da 1 a 30 giorni (default 7)
- 🧹 Pulizia automatica con lock non-bloccante: i segreti scaduti vengono rimossi in background senza interferire con tentativi di sblocco in corso
- 🧼 Distruzione dopo lettura (con sovrascrittura best effort, vedi note sotto)
- 🛡 Mitigazioni anti-abuso: limite 64 KB per segreto, max 5 tentativi password, timing uniforme contro l'enumerazione dei token, validazione tipo input contro request malformate
- 💻 Nessun database richiesto, solo file system

## 🚀 Come funziona

1. Inserisci un messaggio, una password e scegli per quanti giorni il link deve restare valido
2. Ottieni un link nella forma `view.php?token=...#chiave`
3. Invia il link a chi vuoi
4. Il destinatario apre il link, inserisce la password e legge il segreto
5. Il segreto si autodistrugge dopo l'apertura, dopo 5 tentativi falliti, o alla scadenza scelta

## 🛠️ Requisiti

- PHP 7.4+ (consigliato 8.x)
- Estensione OpenSSL abilitata
- Argon2id disponibile (build PHP con libargon2, di default sulle distro moderne)
- Server web con permessi di scrittura, lo script creerà la cartella `data`
- HTTPS configurato a livello webserver (raccomandato, vedi sezione sicurezza)
- JavaScript abilitato lato client (necessario per leggere la chiave dal fragment)
- Filesystem locale (ext4, xfs, btrfs, ntfs). Su NFS/SMB il file locking non è garantito.

## ⚙️ Configurazione

I principali parametri sono costanti in cima a `index.php` e `view.php`:

| Costante | File | Default | Descrizione |
|---|---|---|---|
| `DEFAULT_TTL_DAYS` | index.php | 7 | Giorni di validità di default per i nuovi segreti |
| `MIN_TTL_DAYS` | index.php | 1 | Minimo TTL selezionabile dall'utente |
| `MAX_TTL_DAYS` | index.php | 30 | Massimo TTL selezionabile dall'utente |
| `MAX_SECRET_BYTES` | index.php | 65536 (64 KB) | Limite di dimensione del segreto |
| `MAX_ATTEMPTS` | view.php | 5 | Numero massimo di tentativi password prima della distruzione |
| `CLEANUP_PROB_PCT` | entrambi | 50 | Probabilità (%) di eseguire un cleanup globale a ogni richiesta |
| `TMP_ORPHAN_TTL` | entrambi | 3600 | File temporanei orfani (scritture fallite) più vecchi di X secondi vengono rimossi |
| `LEGACY_TTL_SEC` | entrambi | 7 giorni | TTL fallback per i segreti creati con versioni precedenti (campo `created`) |

Il cleanup globale è probabilistico per ammortizzare il costo: a ogni richiesta c'è il 50% di possibilità che il server scansioni `data/` e rimuova tutti i segreti scaduti e i file temporanei orfani più vecchi di 1 ora. Il cleanup acquisisce un lock esclusivo non-bloccante su ogni file prima di toccarlo, quindi non interferisce mai con tentativi di sblocco o scritture in corso (i file in uso vengono semplicemente saltati e ripresi nelle passate successive).

Per un servizio poco trafficato è un buon compromesso. Se il tuo traffico è molto basso e vuoi essere certo che la pulizia avvenga regolarmente, puoi alzare la percentuale o aggiungere un cron job che chiama una pagina del sito ogni X ore.

## 🔒 Note di sicurezza importanti

**Chiave nel fragment URL.** La chiave AES sta dopo il `#`, quindi non finisce nei log Apache/nginx, nei referer header, nei sistemi di link preview di Slack/WhatsApp/Telegram, nei log di proxy/CDN/WAF. Resta solo nella history del browser del destinatario fino allo sblocco, dopodiché viene rimossa automaticamente via `history.replaceState`.

**Proteggi la cartella `data/`.** Lo script crea `data/` dentro la document root. È **fortemente consigliato** bloccarne l'accesso via web (`.htaccess` con `Deny from all` su Apache, o regola `location` di nega su nginx), oppure spostarla fuori dalla document root modificando `$storage` in `index.php` e `view.php`.

**Forza HTTPS.** Lo script non forza HTTPS perché si presume venga fatto a livello webserver. Senza HTTPS, password e chiavi viaggiano in chiaro.

**Sovrascrittura "secure delete" è best effort.** Su filesystem journaled (ext4, NTFS, APFS, XFS), su SSD con wear leveling, e su setup con backup/snapshot, la sovrascrittura a zeri non garantisce l'irrecuperabilità dei dati. Per una protezione seria a riposo, usa un filesystem cifrato.

**Timing attack su enumerazione token.** Per evitare che un attaccante possa distinguere "token esistente" da "token inesistente" misurando i tempi di risposta, ogni richiesta POST esegue una verifica password (reale o dummy) per consumare lo stesso tempo in entrambi i casi.

**Validazione tipo input.** Tutti gli input HTTP (sia GET che POST) vengono validati come stringhe prima di essere processati, per evitare TypeError 500 e log sporchi causati da bot che forgiano richieste con parametri di tipo array (`?token[]=...`).

**Race condition cleanup vs sblocco.** Il cleanup globale usa `flock LOCK_EX | LOCK_NB` su ogni file prima di leggerlo. Se il file è in uso (perché un'altra richiesta sta facendo l'update del counter dei tentativi, o sta decifrando il segreto), viene saltato silenziosamente e verrà gestito in una passata successiva. Questo evita che un cleanup eseguito durante un legittimo tentativo di sblocco possa distruggere il segreto prima del tempo.

## 🔗 Demo

https://saynomore.muninn.ovh

## ⚠ Attenzione

Tutto quello che pubblico esiste perché serviva a me prima di tutto, non sono uno sviluppatore e potrebbero esserci bug anche critici per quanto tutto il codice sia stato passato su più LLM (Claude, GPT, DeepSeek) alla ricerca di vulnerabilità e dovrebbe essere pulito.

Utilizzate quanto metto a disposizione senza garanzia alcuna.

# Screenshot

Scrivi il tuo segreto, scegli una password e genera il link
![immagine](https://github.com/user-attachments/assets/b967a27f-b716-4c09-ba2e-b09d71696cd0)

Copia il link con il pulsante Copy, o a mano se preferisci, invialo al destinatario
![immagine](https://github.com/user-attachments/assets/e3e0670c-333e-400b-a7cb-7faf429c74cb)

Una volta aperto e inserita la password lo vedrà in questo modo
![immagine](https://github.com/user-attachments/assets/0119ef77-1b1b-45ef-b4b6-591c4b65d502)
