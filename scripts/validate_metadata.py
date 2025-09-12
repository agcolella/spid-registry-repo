#!/usr/bin/env python3
import sys
import re
import urllib.parse
from lxml import etree

# Namespaces
NSMAP = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#"
}

# Utility
def is_https_url(value):
    try:
        parsed = urllib.parse.urlparse(value)
        return parsed.scheme == "https" and bool(parsed.netloc)
    except Exception:
        return False

def is_valid_url(value):
    try:
        parsed = urllib.parse.urlparse(value)
        return parsed.scheme in ["http", "https"] and bool(parsed.netloc)
    except Exception:
        return False

def check(test_id, condition, description, errors):
    if not condition:
        errors.append(f"[{test_id}] {description} ❌")
    else:
        print(f"[{test_id}] {description} ✅")

def main(file_path):
    errors = []
    tree = etree.parse(file_path)
    root = tree.getroot()

    # 1.3 EntityDescriptor
    check("1.3.0", root.tag.endswith("EntityDescriptor"), "EntityDescriptor presente", errors)
    eid = root.attrib.get("entityID")
    check("1.3.1", eid is not None, "entityID presente", errors)
    check("1.3.2", bool(eid), "entityID con valore", errors)

    # 1.6 SPSSODescriptor
    spsso = root.find("md:SPSSODescriptor", namespaces=NSMAP)
    check("1.6.0", spsso is not None, "SPSSODescriptor presente", errors)
    if spsso is not None:
        pse = spsso.attrib.get("protocolSupportEnumeration")
        check("1.6.1", pse is not None, "protocolSupportEnumeration presente", errors)
        check("1.6.2", bool(pse), "protocolSupportEnumeration valorizzato", errors)
        check("1.6.6", "urn:oasis:names:tc:SAML:2.0:protocol" in (pse or ""), "protocolSupportEnumeration contiene SAML2", errors)

        # AuthnRequestsSigned
        ars = spsso.attrib.get("AuthnRequestsSigned")
        check("1.6.3", ars is not None, "AuthnRequestsSigned presente", errors)
        check("1.6.4", bool(ars), "AuthnRequestsSigned valorizzato", errors)
        check("1.6.5", ars == "true", "AuthnRequestsSigned = true", errors)

        # WantAssertionsSigned
        was = spsso.attrib.get("WantAssertionsSigned")
        check("1.6.7", was is not None, "WantAssertionsSigned presente", errors)
        check("1.6.8", bool(was), "WantAssertionsSigned valorizzato", errors)
        check("1.6.9", was == "true", "WantAssertionsSigned = true", errors)

        # 1.1 AssertionConsumerService
        acs = spsso.findall("md:AssertionConsumerService", namespaces=NSMAP)
        check("1.1.0", len(acs) >= 1, "Almeno un AssertionConsumerService presente", errors)
        default_count = 0
        for a in acs:
            idx = a.attrib.get("index")
            bind = a.attrib.get("Binding")
            loc = a.attrib.get("Location")
            is_default = a.attrib.get("isDefault") == "true"
            check("1.1.1", idx is not None, "ACS index presente", errors)
            check("1.1.2", idx is not None and int(idx) >= 0, "ACS index >= 0", errors)
            check("1.1.3", bind is not None, "ACS Binding presente", errors)
            check("1.1.4", bind in [
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            ], "ACS Binding valido", errors)
            check("1.1.5", loc is not None, "ACS Location presente", errors)
            check("1.1.6", loc is not None and is_https_url(loc), "ACS Location è HTTPS valido", errors)
            if is_default:
                default_count += 1
                check("1.1.8", int(idx) == 0, "Default ACS index=0", errors)
        check("1.1.7", default_count == 1, "Un solo ACS default", errors)

        # 1.2 AttributeConsumingService
        attrcs = spsso.findall("md:AttributeConsumingService", namespaces=NSMAP)
        check("1.2.0", len(attrcs) >= 1, "Attributi richiesti presenti", errors)
        for ac in attrcs:
            idx = ac.attrib.get("index")
            check("1.2.1", idx is not None, "AttrCS index presente", errors)
            check("1.2.2", idx is not None and int(idx) >= 0, "AttrCS index >= 0", errors)
            sn = ac.find("md:ServiceName", namespaces=NSMAP)
            check("1.2.3", sn is not None, "ServiceName presente", errors)
            check("1.2.4", sn is not None and bool(sn.text), "ServiceName valorizzato", errors)
            req_attrs = ac.findall("md:RequestedAttribute", namespaces=NSMAP)
            check("1.2.5", len(req_attrs) >= 1, "RequestedAttribute presente", errors)
            for ra in req_attrs:
                name = ra.attrib.get("Name")
                check("1.2.6", name is not None, "RA Name presente", errors)
                allowed = [
                    "address","companyName","companyFiscalNumber","countyOfBirth",
                    "dateOfBirth","digitalAddress","email","expirationDate","familyName",
                    "fiscalNumber","gender","idCard","ivaCode","mobilePhone","name",
                    "placeOfBirth","registeredOffice","spidCode",
                    "domicileStreetAddress","domicilePostalCode","domicileMunicipality",
                    "domicileProvince","domicileNation"
                ]
                check("1.2.7", name in allowed, f"RA Name {name} valido", errors)

    # 1.4 KeyDescriptor
    keys = root.findall(".//md:KeyDescriptor", namespaces=NSMAP)
    signing_keys = [k for k in keys if k.attrib.get("use") in (None,"signing")]
    enc_keys = [k for k in keys if k.attrib.get("use") == "encryption"]
    check("1.4.0", len(signing_keys) >= 1, "Almeno un KeyDescriptor signing", errors)
    for k in signing_keys:
        cert = k.find(".//ds:X509Certificate", namespaces=NSMAP)
        check("1.4.1", cert is not None, "x509 per signing presente", errors)
    for k in enc_keys:
        cert = k.find(".//ds:X509Certificate", namespaces=NSMAP)
        check("1.4.2", cert is not None, "x509 per encryption presente", errors)

    # 1.5 Organization
    orgs = root.findall("md:Organization", namespaces=NSMAP)
    check("1.5.0", len(orgs) == 1, "Un solo Organization", errors)
    if orgs:
        org = orgs[0]
        names = org.findall("md:OrganizationName", namespaces=NSMAP)
        dns = org.findall("md:OrganizationDisplayName", namespaces=NSMAP)
        urls = org.findall("md:OrganizationURL", namespaces=NSMAP)
        check("1.5.1", len(names) >= 1, "OrganizationName presente", errors)
        for n in names:
            check("1.5.2", "lang" in n.attrib, "lang in OrgName", errors)
            check("1.5.3", bool(n.text), "OrgName valorizzato", errors)
        check("1.5.4", len(dns) >= 1, "OrgDisplayName presente", errors)
        for d in dns:
            check("1.5.5", "lang" in d.attrib, "lang in OrgDisplayName", errors)
            check("1.5.6", bool(d.text), "OrgDisplayName valorizzato", errors)
        check("1.5.7", len(urls) >= 1, "OrgURL presente", errors)
        for u in urls:
            check("1.5.8", "lang" in u.attrib, "lang in OrgURL", errors)
            check("1.5.9", bool(u.text), "OrgURL valorizzato", errors)
            check("1.5.10", is_valid_url(u.text), "OrgURL valido", errors)
        # numero lingue coerente
        langs = {len(names), len(dns), len(urls)}
        check("1.5.11", len(langs) == 1, "Stesso numero lingue per OrgName/DisplayName/URL", errors)

    # 1.7 Signature
    sig = root.find("ds:Signature", namespaces=NSMAP)
    check("1.7.0", sig is not None, "Signature presente", errors)
    if sig is not None:
        sm = sig.find("ds:SignedInfo/ds:SignatureMethod", namespaces=NSMAP)
        check("1.7.1", sm is not None, "SignatureMethod presente", errors)
        if sm is not None:
            alg = sm.attrib.get("Algorithm")
            check("1.7.2", alg is not None, "Alg in SignatureMethod", errors)
            allowed_alg = [
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            ]
            check("1.7.3", alg in allowed_alg, f"Alg firma {alg} valido", errors)
        dm = sig.find("ds:SignedInfo/ds:Reference/ds:DigestMethod", namespaces=NSMAP)
        check("1.7.4", dm is not None, "DigestMethod presente", errors)
        if dm is not None:
            dalg = dm.attrib.get("Algorithm")
            check("1.7.5", dalg is not None, "Alg in DigestMethod", errors)
            check("1.7.6", dalg in [
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2001/04/xmlenc#sha384",
                "http://www.w3.org/2001/04/xmlenc#sha512"
            ], f"Digest {dalg} valido", errors)

    # 1.8 SingleLogoutService
    slos = root.findall(".//md:SingleLogoutService", namespaces=NSMAP)
    check("1.8.0", len(slos) >= 1, "SLO presente", errors)
    for s in slos:
        bind = s.attrib.get("Binding")
        loc = s.attrib.get("Location")
        check("1.8.1", bind is not None, "SLO Binding presente", errors)
        check("1.8.2", bool(bind), "SLO Binding valorizzato", errors)
        check("1.8.3", bind in [
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        ], "SLO Binding valido", errors)
        check("1.8.4", loc is not None, "SLO Location presente", errors)
        check("1.8.5", bool(loc), "SLO Location valorizzato", errors)
        check("1.8.6", is_valid_url(loc), "SLO Location è URL valido", errors)

    # Esito finale
    if errors:
        print("\n--- ERRORI ---")
        for e in errors:
            print(e)
        sys.exit(1)
    else:
        print("\nTutti i controlli superati ✅")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: validate_metadata.py <file_metadata.xml>")
        sys.exit(1)
    main(sys.argv[1])
