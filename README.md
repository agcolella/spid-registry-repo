# SPID Registry Repo

[![Validate SPID Metadata](https://github.com/agcolella/spid-registry-repo/actions/workflows/validate.yml/badge.svg)](https://github.com/agcolella/spid-registry-repo/actions/workflows/validate.yml)
[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-online-brightgreen)](https://agcolella.github.io/spid-registry-repo/index.html)

Questo repository contiene i metadata SPID e la pipeline di validazione automatica.


# Registro SPID – Pipeline CI/CD (senza firma digitale)

Questo repository gestisce la **validazione e pubblicazione** dei metadata SPID.  
La pipeline è eseguita con **GitHub Actions** ed è conforme al documento **SPID QAD**.

---

## 📂 Struttura repository

spid-registry-repo/
├── .github/workflows/spid-metadata.yml # Workflow CI/CD
├── metadata/ # File XML dei metadata
├── schemas/spid-metadata.xsd # Schema XSD SPID
├── scripts/
│ ├── validate_metadata.py # Validazione sintattica + QAD
│ ├── check_entityid_unique.py # Controllo duplicati entityID
│ └── rollback_metadata.py # Rollback (solo per GCS, opzionale)
├── requirements.txt
└── README.md

![SPID Registry](https://img.shields.io/endpoint?url=https://agcolella.github.io/spid-registry-repo/badge.json)
---

## ⚙️ Flusso pipeline

1. **Commit di un nuovo metadata** in `metadata/`.
2. GitHub Actions avvia la pipeline:
   - Validazione XSD (`xmllint`).
   - Validazione QAD (`scripts/validate_metadata.py`).
   - Controllo duplicati (`scripts/check_entityid_unique.py`).
   - Pubblicazione su branch `gh-pages` → GitHub Pages.
3. Metadata disponibile su:  
https://agcolella.github.io/spid-registry-repo/metadata/<file>.xml


---

## 📖 Utilizzo locale

### Validazione di un file
```bash
python scripts/validate_metadata.py metadata/idp-test.xml

