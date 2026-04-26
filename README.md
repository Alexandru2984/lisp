# 🚀 Self-Modifying Common Lisp Web Service

## 🔐 Acces rapid
- **URL:** [https://lisp.micutu.com](https://lisp.micutu.com)
- **Utilizator:** `admin`
- **Parolă:** `admin`

---

## ✨ Îmbunătățiri recente (Producție)

1.  **Interfață Modernă (AJAX):**
    - Am integrat **CodeMirror** pentru highlighting de cod Lisp.
    - Evaluarea se face acum instant, fără refresh la pagină, folosind API-uri JSON.
2.  **Securitate Anti-Crash (Timeouts):**
    - Orice expresie Lisp care durează mai mult de **3 secunde** (ex: bucle infinite) este oprită forțat pentru a nu bloca serverul.
3.  **Persistența Datelor:**
    - Funcțiile redefinite prin interfață sunt salvate automat în `data/functions.lisp`.
    - La restartul serviciului, funcțiile tale sunt restaurate automat.
4.  **Cloudflare Real-IP:**
    - Nginx este configurat să vadă IP-ul real al vizitatorului, nu cel de proxy Cloudflare.
5.  **Logging Avansat:**
    - Toate evaluările sunt înregistrate în `logs/evaluations.log` cu timestamp și rezultat.
6.  **Configurare Modulară:**
    - Credențialele și setările de timeout sunt acum în `config/config.lisp`.

---

## 🛠️ Administrare Serviciu
Pentru a vedea ce face aplicația în timp real:
```bash
# Vezi log-urile de execuție
sudo journalctl -u lisp-app -f

# Vezi log-ul de evaluări (ce a introdus lumea în REPL)
tail -f /home/micu/commonLisp/lisp-app/logs/evaluations.log

# Restart serviciu
sudo systemctl restart lisp-app
```

## 🔒 Securitate (Sandbox)
Sandbox-ul blochează accesul la:
- Apeluri de sistem (shell/uiop)
- Ștergere/Modificare fișiere direct din cod
- Expresii care ar putea corupe memoria SBCL
