#!/usr/bin/env python3 -I
"""Compile a String Catalog (.xcstrings) into .strings/.stringsdict for each language.

Xcode compiles String Catalogs with xcstringstool, which isn't part of the Command Line Tools.
This produces the same runtime resources, so the catalog stays the single source of truth.

usage: xcstrings.py Localizable.xcstrings <Resources dir> [table name]
SPDX-License-Identifier: AGPL-3.0-only
"""
import json, os, plistlib, sys

catalog_path, resources = sys.argv[1], sys.argv[2]
table = sys.argv[3] if len(sys.argv) > 3 else "Localizable"
cat = json.load(open(catalog_path, encoding="utf-8"))
source = cat.get("sourceLanguage", "en")

def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

langs = {source}
for entry in cat["strings"].values():
    langs.update(entry.get("localizations", {}).keys())

for lang in sorted(langs):
    plain, plural = {}, {}
    for key, entry in cat["strings"].items():
        loc = entry.get("localizations", {}).get(lang)
        if not loc:
            continue
        if "stringUnit" in loc:
            plain[key] = loc["stringUnit"]["value"]
        elif "variations" in loc and "plural" in loc["variations"]:
            forms = {f: v["stringUnit"]["value"] for f, v in loc["variations"]["plural"].items()}
            # Find the format specifier the forms use (e.g. %lld, %ld) for the value type key.
            spec = next((t for t in ("lld", "ld", "lu", "d", "@") if "%" + t in forms.get("other", "")), "lld")
            rule = {"NSStringFormatSpecTypeKey": "NSStringPluralRuleType", "NSStringFormatValueTypeKey": spec}
            for f, text in forms.items():
                rule[f] = text.replace("%" + spec, "%" + spec, 1)
            plural[key] = {"NSStringLocalizedFormatKey": "%#@count@", "count": rule}
    d = os.path.join(resources, f"{lang}.lproj")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"{table}.strings"), "w", encoding="utf-8") as f:
        for k in sorted(plain):
            f.write(f'"{esc(k)}" = "{esc(plain[k])}";\n')
    if plural:
        with open(os.path.join(d, f"{table}.stringsdict"), "wb") as f:
            plistlib.dump(plural, f, fmt=plistlib.FMT_XML, sort_keys=True)
    print(f"{lang}: {len(plain)} strings, {len(plural)} plurals")
