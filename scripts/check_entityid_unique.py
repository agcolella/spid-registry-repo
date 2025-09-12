#!/usr/bin/env python3
"""
check_entityid_unique.py

Controlla che non ci siano duplicati di entityID nei file XML della cartella metadata/.
Esce con codice 1 se rileva duplicati, altrimenti 0.
"""

import os
import sys
from lxml import etree

# Directory metadata (relativa alla root del repository)
METADATA_DIR = os.path.join(os.path.dirname(__file__), "..", "metadata")

def extract_entity_id(file_path):
    """Estrae l'attributo entityID da un file XML."""
    try:
        tree = etree.parse(file_path)
        root = tree.getroot()
        return root.attrib.get("entityID")
    except Exception as e:
        print(f"[ERRORE] Impossibile leggere {file_path}: {e}")
        return None

def main():
    seen = {}
    duplicates = []

    # Scansione della cartella metadata/
    for fname in os.listdir(METADATA_DIR):
        if fname.endswith(".xml"):
            fpath = os.path.join(METADATA_DIR, fname)
            eid = extract_entity_id(fpath)
            if eid:
                if eid in seen:
                    duplicates.append((eid, fname, seen[eid]))
                else:
                    seen[eid] = fname

    # Esito finale
    if duplicates:
        print("❌ Duplicati trovati negli EntityID:")
        for eid, f1, f2 in duplicates:
            print(f" - {eid} presente in {f1} e {f2}")
        sys.exit(1)
    else:
        print("✅ Nessun duplicato trovato negli EntityID")
        sys.exit(0)

if __name__ == "__main__":
    main()
