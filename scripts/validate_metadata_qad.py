#!/usr/bin/env python3
"""
validate_metadata_qad.py

Validatore dei Metadata SPID basato sui controlli principali del QAD (Metadata),
esteso con:
 - verifica firma XML (richiede xmlsec1 CLI)
 - verifica catena di fiducia dei certificati (richiede openssl; usa bundle certifi per default)

Output: console text.
Exit codes:
 - 0: OK (nessun errore di validazione)
 - 1: errori di validazione
 - 2: errori di uso / IO / ambiente

Install:
  pip install lxml cryptography certifi

System tools:
  xmlsec1, openssl

Uso:
  python scripts/validate_metadata_qad.py metadata/<file>.xml [--ca-bundle /path/to/ca-bundle.crt]
"""

import sys
import os
import subprocess
import tempfile
import base64
import datetime
import shutil
import argparse
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec as _ec
from cryptography.hazmat.backends import default_backend
import certifi

# Namespace map
NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xml": "http://www.w3.org/XML/1998/namespace"
}

# Allowed values
ALLOWED_ACS_BINDINGS = {
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
}
ALLOWED_SLO_BINDINGS = {
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
}
ALLOWED_SIGNATURE_ALGS = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
}
ALLOWED_DIGEST_ALGS = {
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmlenc#sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512",
}
ALLOWED_REQUESTED_ATTRIBUTES = {
    "name", "familyName", "fiscalNumber", "email", "mobilePhone",
    "placeOfBirth", "dateOfBirth", "gender", "spidCode", "companyName",
    "ivaCode", "idCard", "registeredOffice", "domicileStreetAddress",
    "domicilePostalCode", "domicileMunicipality", "domicileProvince",
    "domicileNation", "address"
}
MIN_RSA_KEY_SIZE = 2048
MIN_EC_CURVES = {"secp256r1", "secp384r1", "secp521r1"}  # names reported by cryptography

# Helpers for console messages
def ok(code, desc):
    print(f"[{code}] {desc} ✅")

def err(code, desc, errors):
    print(f"[{code}] {desc} ❌")
    errors.append(f"[{code}] {desc}")

def fatal(msg):
    print(f"[FATAL] {msg}")
    sys.exit(2)

# XML load
def load_xml(path):
    if not os.path.isfile(path):
        fatal(f"File non trovato: {path}")
    parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
    try:
        tree = etree.parse(path, parser)
        return tree
    except Exception as e:
        fatal(f"Impossibile parsare XML {path}: {e}")

# Certificate helpers
def extract_cert_nodes_from_keydescriptor(kd):
    """
    Ritorna lista di nodi ds:X509Certificate (lxml elements) trovati dentro un KeyDescriptor.
    """
    return kd.findall(".//ds:X509Certificate", namespaces=NS)

def parse_x509_from_b64_text(b64text):
    if not b64text:
        return None, "no-data"
    try:
        der = base64.b64decode("".join(b64text.split()))
    except Exception as e:
        return None, f"base64-decode-error:{e}"
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        return cert, None
    except Exception as e:
        return None, f"load-der-error:{e}"

def check_cert_basic(cert):
    """
    Controlli base: validità temporale, tipo chiave e lunghezza / curve.
    Ritorna lista di messaggi di errore (vuota se ok).
    """
    errs = []
    now = datetime.datetime.utcnow()
    try:
        if cert.not_valid_after < now:
            errs.append("certificate expired")
        if cert.not_valid_before > now + datetime.timedelta(seconds=10):
            errs.append("certificate not yet valid")
    except Exception:
        errs.append("certificate validity info missing")

    pub = cert.public_key()
    # RSA
    if isinstance(pub, rsa.RSAPublicKey):
        size = pub.key_size
        if size < MIN_RSA_KEY_SIZE:
            errs.append(f"rsa key too small ({size} bits)")
    else:
        # try EC
        try:
            if isinstance(pub, _ec.EllipticCurvePublicKey):
                curve_name = pub.curve.name
                if curve_name not in MIN_EC_CURVES:
                    errs.append(f"ec curve not allowed ({curve_name})")
            else:
                errs.append("unsupported public key type")
        except Exception:
            errs.append("unable to determine public key type")

    return errs

# XML Signature verification via xmlsec1 CLI
def is_tool_installed(name):
    return shutil.which(name) is not None

def verify_xml_signature_with_xmlsec(xml_path):
    """
    Verifica la firma XML usando xmlsec1 CLI. Ritorna (ok_bool, output_str).
    xmlsec1 --verify --quiet <file>
    xmlsec1 returns 0 for verified; non-zero otherwise.
    """
    if not is_tool_installed("xmlsec1"):
        return None, "xmlsec1 not installed"
    try:
        # Use --verify; xmlsec1 will try to use KeyInfo inside signature to verify
        p = subprocess.run(["xmlsec1", "--verify", xml_path], capture_output=True, text=True)
        out = p.stdout + "\n" + p.stderr
        return (p.returncode == 0), out
    except Exception as e:
        return False, f"xmlsec1 invocation error: {e}"

# Certificate chain verification via openssl verify
def verify_cert_chain_with_openssl(cert_obj, ca_bundle_path=None):
    """
    Scrive il certificato temporaneamente come PEM e chiama:
      openssl verify -CAfile <ca_bundle> cert.pem
    Se ca_bundle_path is None, usa certifi.where().
    Ritorna (ok_bool, output_str)
    """
    if not is_tool_installed("openssl"):
        return None, "openssl not installed"

    if ca_bundle_path is None:
        ca_bundle_path = certifi.where()

    with tempfile.TemporaryDirectory() as td:
        cert_pem_path = os.path.join(td, "cert.pem")
        try:
            pem = cert_obj.public_bytes(encoding=x509.Encoding.PEM)
        except Exception:
            # use private method to produce PEM
            pem = cert_obj.public_bytes(encoding=x509.Encoding.PEM)
        with open(cert_pem_path, "wb") as f:
            f.write(pem)
        try:
            p = subprocess.run(["openssl", "verify", "-CAfile", ca_bundle_path, cert_pem_path],
                               capture_output=True, text=True)
            out = p.stdout + "\n" + p.stderr
            return (p.returncode == 0), out
        except Exception as e:
            return False, f"openssl invocation error: {e}"

# QAD checks implementation
def run_qad_checks(root, xml_path, ca_bundle=None):
    errors = []
    # 1.3 EntityDescriptor
    if root.tag is None or not root.tag.endswith("EntityDescriptor"):
        err("1.3.0", "EntityDescriptor presente", errors)
    else:
        ok("1.3.0", "EntityDescriptor presente")
    eid = root.attrib.get("entityID")
    if not eid:
        err("1.3.1", "entityID presente", errors)
    else:
        ok("1.3.1", f"entityID presente ({eid})")

    # SPSSODescriptor checks (if present)
    spsso = root.find("md:SPSSODescriptor", namespaces=NS)
    if spsso is not None:
        ok("1.6.0", "SPSSODescriptor presente")
        pse = spsso.attrib.get("protocolSupportEnumeration", "")
        if "urn:oasis:names:tc:SAML:2.0:protocol" in pse:
            ok("1.6.6", "protocolSupportEnumeration contains SAML2")
        else:
            err("1.6.6", "protocolSupportEnumeration does not contain SAML2", errors)

        # AuthnRequestsSigned
        ars = spsso.attrib.get("AuthnRequestsSigned")
        if ars is None:
            err("1.6.3", "AuthnRequestsSigned presente", errors)
        else:
            if ars.lower() == "true":
                ok("1.6.5", "AuthnRequestsSigned = true")
            else:
                err("1.6.5", f"AuthnRequestsSigned = {ars} (expected true)", errors)

        was = spsso.attrib.get("WantAssertionsSigned")
        if was is None:
            err("1.6.7", "WantAssertionsSigned presente", errors)
        else:
            if was.lower() == "true":
                ok("1.6.9", "WantAssertionsSigned = true")
            else:
                err("1.6.9", f"WantAssertionsSigned = {was} (expected true)", errors)
    else:
        ok("1.6.0", "SPSSODescriptor non presente (probabilmente IDP metadata)")

    # AssertionConsumerService checks
    if spsso is not None:
        acs_nodes = spsso.findall("md:AssertionConsumerService", namespaces=NS)
        if not acs_nodes:
            err("1.1.0", "Almeno un AssertionConsumerService presente", errors)
        else:
            ok("1.1.0", f"AssertionConsumerService count = {len(acs_nodes)}")
            default_count = 0
            for acs in acs_nodes:
                idx = acs.attrib.get("index")
                bind = acs.attrib.get("Binding")
                loc = acs.attrib.get("Location")
                is_default = acs.attrib.get("isDefault", "").lower() == "true"
                if idx is None:
                    err("1.1.1", "ACS index presente", errors)
                else:
                    try:
                        if int(idx) >= 0:
                            ok("1.1.2", f"ACS index >= 0 ({idx})")
                        else:
                            err("1.1.2", f"ACS index negativo ({idx})", errors)
                    except Exception:
                        err("1.1.2", f"ACS index non numerico ({idx})", errors)
                if bind is None:
                    err("1.1.3", "ACS Binding presente", errors)
                else:
                    if bind in ALLOWED_ACS_BINDINGS:
                        ok("1.1.4", f"ACS Binding valido ({bind})")
                    else:
                        err("1.1.4", f"ACS Binding non valido ({bind})", errors)
                if loc is None:
                    err("1.1.5", "ACS Location presente", errors)
                else:
                    if loc.lower().startswith("https://"):
                        ok("1.1.6", f"ACS Location HTTPS ({loc})")
                    else:
                        err("1.1.6", f"ACS Location non HTTPS ({loc})", errors)
                if is_default:
                    default_count += 1
                    if idx is not None and int(idx) == 0:
                        ok("1.1.8", "Default ACS index = 0")
                    else:
                        err("1.1.8", "Default ACS index non = 0", errors)
            if default_count == 1:
                ok("1.1.7", "Un solo ACS default")
            else:
                err("1.1.7", f"Default ACS count = {default_count}", errors)

    # AttributeConsumingService / RequestedAttribute
    attr_cs_nodes = root.findall(".//md:AttributeConsumingService", namespaces=NS)
    if not attr_cs_nodes:
        err("1.2.0", "AttributeConsumingService presente", errors)
    else:
        ok("1.2.0", f"AttributeConsumingService count = {len(attr_cs_nodes)}")
        for ac in attr_cs_nodes:
            idx = ac.attrib.get("index")
            if idx is None:
                err("1.2.1", "AttrCS index presente", errors)
            else:
                try:
                    if int(idx) >= 0:
                        ok("1.2.2", f"AttrCS index >= 0 ({idx})")
                    else:
                        err("1.2.2", f"AttrCS index negativo ({idx})", errors)
                except Exception:
                    err("1.2.2", f"AttrCS index non numerico ({idx})", errors)
            sn = ac.find("md:ServiceName", namespaces=NS)
            if sn is None or (sn.text or "").strip() == "":
                err("1.2.3", "ServiceName presente e valorizzato", errors)
            else:
                ok("1.2.4", "ServiceName valorizzato")
            ras = ac.findall("md:RequestedAttribute", namespaces=NS)
            if not ras:
                err("1.2.5", "RequestedAttribute presente", errors)
            else:
                for ra in ras:
                    name = ra.attrib.get("Name")
                    if not name:
                        err("1.2.6", "RequestedAttribute Name presente", errors)
                    else:
                        if name in ALLOWED_REQUESTED_ATTRIBUTES:
                            ok("1.2.7", f"RequestedAttribute Name valido ({name})")
                        else:
                            # In QAD this may be a warning, but we mark as error for strictness
                            err("1.2.7", f"RequestedAttribute Name non riconosciuto ({name})", errors)

    # KeyDescriptor / certificates checks
    keydescs = root.findall(".//md:KeyDescriptor", namespaces=NS)
    if not keydescs:
        err("1.4.0", "Almeno un KeyDescriptor presente", errors)
    else:
        signing_count = 0
        for kd in keydescs:
            use = kd.attrib.get("use", "signing")
            if use == "encryption":
                # encryption key optional in many SP configs
                pass
            else:
                signing_count += 1
            cert_nodes = extract_cert_nodes_from_keydescriptor(kd)
            if not cert_nodes:
                err("1.4.1", f"X509Certificate mancante in KeyDescriptor (use={use})", errors)
            else:
                for cn in cert_nodes:
                    cert_text = (cn.text or "").strip()
                    cert_obj, parse_err = parse_x509_from_b64_text(cert_text)
                    if cert_obj is None:
                        err("1.4.1", f"Parsing X509 failed: {parse_err}", errors)
                    else:
                        ok("1.4.1", "X509 parsed successfully")
                        # basic checks
                        cert_errs = check_cert_basic(cert_obj)
                        if cert_errs:
                            for ce in cert_errs:
                                err("1.4.1", f"Cert issue: {ce}", errors)
                        else:
                            ok("1.4.1", "Cert validity and key strength OK")
                        # chain verify (openssl) if requested
                        chain_ok, chain_out = verify_cert_chain_with_openssl(cert_obj, ca_bundle_path=ca_bundle)
                        if chain_ok is None:
                            print("[INF] openssl not installed: skipping chain verification")
                        else:
                            if chain_ok:
                                ok("1.4.10", "Cert chain verification OK (openssl)")
                            else:
                                err("1.4.10", f"Cert chain verification FAILED: {chain_out.strip()}", errors)

        if signing_count >= 1:
            ok("1.4.0", f"KeyDescriptor signing count >=1 ({signing_count})")
        else:
            err("1.4.0", "Nessun KeyDescriptor signing trovato", errors)

    # Organization checks (it/en)
    org_nodes = root.findall(".//md:Organization", namespaces=NS)
    if not org_nodes:
        err("1.5.0", "Organization presente (1 sola)", errors)
    else:
        if len(org_nodes) != 1:
            err("1.5.0", f"Numero Organization != 1 ({len(org_nodes)})", errors)
        else:
            org = org_nodes[0]
            names = org.findall("md:OrganizationName", namespaces=NS)
            dns = org.findall("md:OrganizationDisplayName", namespaces=NS)
            urls = org.findall("md:OrganizationURL", namespaces=NS)
            # require both it and en
            langs_names = {n.attrib.get("{http://www.w3.org/XML/1998/namespace}lang") for n in names}
            langs_dns = {d.attrib.get("{http://www.w3.org/XML/1998/namespace}lang") for d in dns}
            langs_urls = {u.attrib.get("{http://www.w3.org/XML/1998/namespace}lang") for u in urls}
            if {"it", "en"}.issubset(langs_names):
                ok("1.5.2", "OrganizationName includes it/en")
            else:
                err("1.5.2", f"OrganizationName languages missing: {langs_names}", errors)
            if {"it", "en"}.issubset(langs_dns):
                ok("1.5.5", "OrganizationDisplayName includes it/en")
            else:
                err("1.5.5", f"OrganizationDisplayName languages missing: {langs_dns}", errors)
            if {"it", "en"}.issubset(langs_urls):
                ok("1.5.8", "OrganizationURL includes it/en")
            else:
                err("1.5.8", f"OrganizationURL languages missing: {langs_urls}", errors)
            if len(names) == len(dns) == len(urls):
                ok("1.5.11", "Numero lingue coerente per OrgName/DisplayName/URL")
            else:
                err("1.5.11", f"Numero lingue non coerente (names={len(names)}, display={len(dns)}, url={len(urls)})", errors)

    # Signature presence and algorithm checks (and xmlsec verification)
    sig = root.find(".//ds:Signature", namespaces=NS)
    if sig is None:
        err("1.7.0", "Signature presente", errors)
    else:
        ok("1.7.0", "Signature presente")
        sm = sig.find("ds:SignedInfo/ds:SignatureMethod", namespaces=NS)
        if sm is None:
            err("1.7.1", "SignatureMethod presente", errors)
        else:
            alg = sm.attrib.get("Algorithm")
            if alg in ALLOWED_SIGNATURE_ALGS:
                ok("1.7.3", f"Alg signature permitted ({alg})")
            else:
                err("1.7.3", f"Alg signature not permitted ({alg})", errors)
        dm = sig.find("ds:SignedInfo/ds:Reference/ds:DigestMethod", namespaces=NS)
        if dm is None:
            err("1.7.4", "DigestMethod presente", errors)
        else:
            dalg = dm.attrib.get("Algorithm")
            if dalg in ALLOWED_DIGEST_ALGS:
                ok("1.7.6", f"DigestMethod permitted ({dalg})")
            else:
                err("1.7.6", f"DigestMethod not permitted ({dalg})", errors)

        # XML signature cryptographic verification using xmlsec1
        xmlsec_result, xmlsec_out = verify_xml_signature_with_xmlsec(xml_path)
        if xmlsec_result is None:
            print("[INF] xmlsec1 not installed: skipping xml signature verification")
        else:
            if xmlsec_result:
                ok("1.7.20", "XML signature cryptographic verification OK (xmlsec1)")
            else:
                err("1.7.20", f"XML signature verification FAILED: {xmlsec_out.strip()}", errors)

    # SingleLogoutService presence and binding check
    slos = root.findall(".//md:SingleLogoutService", namespaces=NS)
    if not slos:
        err("1.8.0", "SingleLogoutService presente", errors)
    else:
        ok("1.8.0", f"SingleLogoutService count = {len(slos)}")
        if any((slo.attrib.get("Binding") in ALLOWED_SLO_BINDINGS) for slo in slos):
            ok("1.8.3", "SLO Binding valido trovato")
        else:
            err("1.8.3", "Nessun SLO Binding valido trovato", errors)

    # ContactPerson minimal check
    contacts = root.findall(".//md:ContactPerson", namespaces=NS)
    if not contacts:
        err("1.6.100", "ContactPerson presente (minimo 1)", errors)
    else:
        ok("1.6.100", f"ContactPerson count = {len(contacts)}")

    return errors

# Arg parsing main
def main():
    ap = argparse.ArgumentParser(description="Validate SPID metadata per QAD (metadata checks + xmlsec + chain verify).")
    ap.add_argument("xmlfile", help="File metadata XML da validare")
    ap.add_argument("--ca-bundle", help="Percorso a file bundle CA (PEM). Se omesso usa certifi", default=None)
    args = ap.parse_args()

    xmlfile = args.xmlfile
    ca_bundle = args.ca_bundle

    if ca_bundle is None:
        ca_bundle = certifi.where()

    root = load_xml(xmlfile)
    errors = run_qad_checks(root, xmlfile, ca_bundle)

    print("\n--- REPORT ---")
    if errors:
        print("ERRORS FOUND:")
        for e in errors:
            print(e)
        print(f"\nValidation FAILED: {len(errors)} error(s).")
        sys.exit(1)
    else:
        print("No errors found. Metadata OK according to QAD checks implemented.")
        sys.exit(0)

if __name__ == "__main__":
    main()
