#!/usr/bin/env python3
"""
validate_metadata_qad.py

Validatore SPID Metadata secondo QAD.
Esegue controlli sintattici e semantici, verifica opzionale della firma XML
(se xmlsec1 è installato) e scadenza dei certificati (self-signed accettati).

Usage:
    python scripts/validate_metadata_qad.py <metadata.xml>
"""

import os
import sys
import subprocess
import shutil
from datetime import datetime, timezone
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Namespaces comuni
NSMAP = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

# Bindings ammessi
ALLOWED_SLO_BINDINGS = {
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
}


def parse_xml(path):
    """Carica XML e restituisce il nodo radice."""
    try:
        parser = etree.XMLParser(remove_blank_text=True)
        tree = etree.parse(path, parser)
        return tree.getroot()
    except Exception as e:
        print(f"[ERRORE] parsing {path}: {e}")
        sys.exit(2)


def check_lang(elements, tag, errors, code):
    """Verifica presenza di it/en su elementi localizzati."""
    langs = {el.attrib.get("{http://www.w3.org/XML/1998/namespace}lang") for el in elements}
    if not {"it", "en"}.issubset(langs):
        errors.append(f"[{code}] {tag} deve avere almeno 'it' e 'en' ❌")


def check_signature(xmlfile):
    """Verifica la firma XML usando xmlsec1 se disponibile. Warning se non valida."""
    if not shutil.which("xmlsec1"):
        print("[WARN] xmlsec1 non trovato, skip firma")
        return
    try:
        res = subprocess.run(
            ["xmlsec1", "--verify", "--insecure", xmlfile],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            print(f"[WARN] Firma non valida o mancante in {xmlfile}")
    except Exception as e:
        print(f"[WARN] Errore durante verifica firma: {e}")


def check_certificates(root, errors):
    """Estrae certificati e controlla la scadenza (self-signed accettati)."""
    certs = root.findall(".//ds:X509Certificate", NSMAP)
    for idx, node in enumerate(certs, start=1):
        try:
            pem = (
                "-----BEGIN CERTIFICATE-----\n"
                + node.text.strip()
                + "\n-----END CERTIFICATE-----\n"
            )
            cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
            # controllo scadenza con not_valid_after_utc + timezone.utc
            if cert.not_valid_after_utc < datetime.now(timezone.utc):
                errors.append(f"[Cert {idx}] Certificato scaduto il {cert.not_valid_after_utc} ❌")
        except Exception as e:
            errors.append(f"[Cert {idx}] Errore parsing certificato: {e}")


def run_qad_checks(root, xmlfile):
    errors = []

    if root.tag is None or not root.tag.endswith("EntityDescriptor"):
        errors.append("[1.1] Root deve essere EntityDescriptor ❌")

    # 1.5.2 OrgName
    org_names = root.findall(".//md:OrganizationName", NSMAP)
    check_lang(org_names, "OrgName", errors, "1.5.2")

    # 1.5.5 OrgDisplayName
    org_disp = root.findall(".//md:OrganizationDisplayName", NSMAP)
    check_lang(org_disp, "OrgDisplayName", errors, "1.5.5")

    # 1.5.8 OrgURL
    org_urls = root.findall(".//md:OrganizationURL", NSMAP)
    check_lang(org_urls, "OrgURL", errors, "1.5.8")

    # 1.8.3 SingleLogoutService binding
    slos = root.findall(".//md:SingleLogoutService", NSMAP)
    if not any(slo.attrib.get("Binding") in ALLOWED_SLO_BINDINGS for slo in slos):
        errors.append("[1.8.3] Nessun SingleLogoutService con binding valido ❌")

    # Firma XML (solo warning se invalida)
    check_signature(xmlfile)

    # Certificati (solo scadenza)
    check_certificates(root, errors)

    return errors


def main():
    if len(sys.argv) != 2:
        print("Uso: validate_metadata_qad.py <metadata.xml>")
        sys.exit(1)

    xmlfile = sys.argv[1]
    if not os.path.exists(xmlfile):
        print(f"[ERRORE] File non trovato: {xmlfile}")
        sys.exit(1)

    root = parse_xml(xmlfile)
    errors = run_qad_checks(root, xmlfile)

    if errors:
        print(f"--- ERRORI in {xmlfile} ---")
        for e in errors:
            print(e)
        sys.exit(1)
    else:
        print(f"✅ {xmlfile} valido secondo QAD")
        sys.exit(0)


if __name__ == "__main__":
    main()
