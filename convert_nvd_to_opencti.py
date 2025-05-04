import json
import uuid
import re
import csv
import gzip
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse
from dateutil.parser import parse as parse_datetime
from stix2 import Vulnerability, ExternalReference, Bundle, Relationship, Software, Identity

# 識別子パターン
ID_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{4,}"),
    re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"),
    re.compile(r"ZDI-\d{2}-\d{3,}"),
    re.compile(r"JVNDB-\d{4}-\d{6}"),
    re.compile(r"JVNTA#\d{8}"),
    re.compile(r"BID-\d+"),
    re.compile(r"VU#\d+"),
    re.compile(r"MS\d{2}-\d{3}")
]

def load_cisa_kev_ids(filename="cisa_known_exploited_vulnerabilities.json"):
    if not os.path.isfile(filename):
        print("⚠️ CISA KEVファイルが見つかりません。スキップします。")
        return set()
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {entry["cveID"] for entry in data.get("vulnerabilities", [])}

def load_epss_scores(filename="epss_scores-current.csv.gz"):
    if not os.path.isfile(filename):
        print("⚠️ EPSSファイルが見つかりません。スキップします。")
        return {}
    epss_data = {}
    with gzip.open(filename, mode="rt", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            epss_data[row["cve"]] = {
                "score": float(row["epss"]),
                "percentile": float(row["percentile"])
            }
    print(f"✅ EPSSスコア {len(epss_data)} 件読み込み完了")
    return epss_data

def extract_external_references(reference_data):
    refs = []
    for ref in reference_data:
        url = ref.get("url", "")
        name = ref.get("name", "")
        tags = ref.get("tags", [])
        parsed_url = urlparse(url)
        domain = parsed_url.hostname or "external"
        if domain.startswith("www."):
            domain = domain[4:]

        source_name = domain if url == name else name
        if tags:
            tag_str = ", ".join(tags)
            source_name += f"_[ {tag_str} ]"

        external_id = None
        for pattern in ID_PATTERNS:
            match = pattern.search(name) or pattern.search(url)
            if match:
                external_id = match.group(0)
                break

        ref_dict = {
            "source_name": source_name,
            "url": url,
            "description": name
        }
        if external_id:
            ref_dict["external_id"] = external_id

        refs.append(ExternalReference(**ref_dict))
    return refs

def extract_cpes(configurations):
    cpes = []
    for node in configurations.get("nodes", []):
        for cpe in node.get("cpe_match", []):
            if "cpe23Uri" in cpe:
                cpes.append(cpe["cpe23Uri"])
    return cpes

def extract_software_name_from_cpe(cpe_uri):
    try:
        parts = cpe_uri.split(":")
        part = parts[2] if len(parts) > 2 else ""
        product = parts[4] if len(parts) > 4 else "unknown"
        version = parts[5] if len(parts) > 5 and parts[5] != "*" else None
        suffix = {"o": "_OS", "h": "_HW", "a": "_App"}.get(part, "")
        name = f"{product}_{version}" if version else product
        return name + suffix
    except:
        return cpe_uri

def extract_vendor_from_cpe(cpe_uri):
    try:
        parts = cpe_uri.split(":")
        return parts[3] if len(parts) > 3 else None
    except:
        return None

def extract_cvss(impact):
    if "baseMetricV3" in impact:
        cvss = impact["baseMetricV3"]["cvssV3"]
        return {
            "version": "v3",
            "score": cvss["baseScore"],
            "severity": cvss["baseSeverity"],
            "attack_vector": cvss["attackVector"],
            "confidentiality_impact": cvss["confidentialityImpact"],
            "integrity_impact": cvss["integrityImpact"],
            "availability_impact": cvss["availabilityImpact"]
        }
    elif "baseMetricV2" in impact:
        cvss = impact["baseMetricV2"]["cvssV2"]
        return {
            "version": "v2",
            "score": impact["baseMetricV2"]["score"],
            "severity": "N/A",
            "attack_vector": cvss["accessVector"],
            "confidentiality_impact": cvss["confidentialityImpact"],
            "integrity_impact": cvss["integrityImpact"],
            "availability_impact": cvss["availabilityImpact"]
        }
    else:
        return None

def parse_nvd_datetime(value):
    try:
        return parse_datetime(value)
    except:
        return datetime.now(timezone.utc)

def process_all(cve_items, cisa_set, epss_scores):
    objects = []
    vendor_cache = {}

    for item in cve_items:
        cve = item["cve"]
        cve_id = cve["CVE_data_meta"]["ID"]
        description = next((d["value"] for d in cve["description"]["description_data"] if d["lang"] == "en"), "No description")

        cvss_data = extract_cvss(item.get("impact", {}))
        if cvss_data and cvss_data["version"] == "v2":
            description += "\n\n※ この脆弱性は CVSSv2 で記載されています。"

        published = parse_nvd_datetime(item.get("publishedDate"))
        modified = parse_nvd_datetime(item.get("lastModifiedDate"))
        vuln_id = f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_DNS, cve_id)}"

        refs = extract_external_references(cve.get("references", {}).get("reference_data", []))

        custom_fields = {
            "x_opencti_cvss_base_score": cvss_data.get("score") if cvss_data else None,
            "x_opencti_cvss_base_severity": cvss_data.get("severity") if cvss_data else None,
            "x_opencti_cvss_attack_vector": cvss_data.get("attack_vector") if cvss_data else None,
            "x_opencti_cvss_confidentiality_impact": cvss_data.get("confidentiality_impact") if cvss_data else None,
            "x_opencti_cvss_integrity_impact": cvss_data.get("integrity_impact") if cvss_data else None,
            "x_opencti_cvss_availability_impact": cvss_data.get("availability_impact") if cvss_data else None,
            "x_opencti_cisa_kev": cve_id in cisa_set
        }

        epss = epss_scores.get(cve_id)
        if epss:
            custom_fields["x_opencti_epss_score"] = epss["score"]
            custom_fields["x_opencti_epss_percentile"] = epss["percentile"]

        vuln = Vulnerability(
            id=vuln_id,
            name=cve_id,
            description=description,
            created=published,
            modified=modified,
            external_references=refs,
            allow_custom=True,
            **custom_fields
        )
        objects.append(vuln)

        for cpe in extract_cpes(item.get("configurations", {})):
            cpe_id = f"software--{uuid.uuid5(uuid.NAMESPACE_DNS, cpe)}"
            software = Software(
                id=cpe_id,
                name=extract_software_name_from_cpe(cpe),
                description=cpe,
                created=published,
                modified=modified,
                allow_custom=True
            )
            objects.append(software)

            rel = Relationship(
                id=f"relationship--{uuid.uuid4()}",
                relationship_type="has",
                source_ref=cpe_id,
                target_ref=vuln_id,
                created=published,
                modified=modified,
                confidence=100,
                allow_custom=True
            )
            objects.append(rel)

            vendor = extract_vendor_from_cpe(cpe)
            if vendor:
                if vendor not in vendor_cache:
                    org_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, vendor)}"
                    organization = Identity(
                        id=org_id,
                        identity_class="organization",
                        name=vendor,
                        created=published,
                        modified=modified
                    )
                    vendor_cache[vendor] = org_id
                    objects.append(organization)

                rel_org = Relationship(
                    id=f"relationship--{uuid.uuid4()}",
                    relationship_type="related-to",
                    source_ref=cpe_id,
                    target_ref=vendor_cache[vendor],
                    created=published,
                    modified=modified,
                    confidence=100,
                    allow_custom=True
                )
                objects.append(rel_org)

    bundle = Bundle(objects=objects, id=f"bundle--{uuid.uuid4()}", allow_custom=True)
    with open("output_opencti_stix.json", "w", encoding="utf-8") as f:
        f.write(bundle.serialize())
    print("✅ 出力完了: output_opencti_stix.json")

# 実行部
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使い方: python convert_nvd_to_opencti.py <nvd_jsonファイル>")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.isfile(input_file):
        print(f"エラー: ファイルが見つかりません → {input_file}")
        sys.exit(1)

    with open(input_file, "r", encoding="utf-8") as f:
        nvd_data = json.load(f)

    cve_items = nvd_data.get("CVE_Items", [])
    cisa_set = load_cisa_kev_ids()
    epss_scores = load_epss_scores()

    process_all(cve_items, cisa_set, epss_scores)
