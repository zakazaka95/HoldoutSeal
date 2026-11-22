"""Offline corpus commitment helper. Never imports GenLayer or calls a network.

Use deployment context already known before opening a benchmark. Do not send the
salt or corpus to an onchain helper/view before enrollment closes.
"""
import hashlib
import json
import sys


DOMAIN = "holdoutseal-corpus-v1"


def text(value, maximum, minimum=1):
    if not isinstance(value, str) or not value.strip() or not minimum <= len(value) <= maximum:
        raise ValueError("Text is outside its bounds")
    value.encode("utf-8")
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Integer is outside its bounds")
    return value


def address(value):
    if (not isinstance(value, str) or len(value) != 42 or value[:2].lower() != "0x"
            or any(c not in "0123456789abcdefABCDEF" for c in value[2:]) or int(value[2:], 16) == 0):
        raise ValueError("A nonzero hexadecimal address is required")
    return value.lower()


def canonical_spec(raw):
    fields = {"title", "purpose", "label_rule", "candidates", "case_count", "max_false_allows",
              "max_false_denies", "nonce", "enrollment_seconds", "reveal_seconds", "evaluation_seconds"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ValueError("Specification keys differ")
    result = {"title": text(raw["title"], 100), "purpose": text(raw["purpose"], 400),
              "label_rule": text(raw["label_rule"], 500), "nonce": text(raw["nonce"], 80)}
    if not isinstance(raw["candidates"], list) or not 1 <= len(raw["candidates"]) <= 4:
        raise ValueError("Candidate count is outside its bounds")
    addresses = [address(value) for value in raw["candidates"]]
    if len(set(addresses)) != len(addresses):
        raise ValueError("Candidate addresses repeat")
    result["candidates"] = sorted(addresses)
    result["case_count"] = integer(raw["case_count"], 4, 6)
    result["max_false_allows"] = integer(raw["max_false_allows"], 0, 4)
    result["max_false_denies"] = integer(raw["max_false_denies"], 0, 4)
    for key in ["enrollment_seconds", "reveal_seconds", "evaluation_seconds"]:
        result[key] = integer(raw[key], 60, 86400)
    if max(2, result["max_false_denies"] + 1) > min(result["case_count"] - 2, result["case_count"] - result["max_false_allows"] - 1):
        raise ValueError("Error caps admit no legal represented corpus")
    return result


def canonical_cases(raw, spec):
    if not isinstance(raw, list) or len(raw) != spec["case_count"]:
        raise ValueError("A complete corpus is required")
    cases = []
    for i, row in enumerate(raw):
        if (not isinstance(row, dict) or set(row) != {"case_id", "text", "expected"}
                or type(row["case_id"]) is not int or row["case_id"] != i
                or row["expected"] not in ["ALLOW", "DENY"]):
            raise ValueError("Case schema differs")
        cases.append({"case_id": i, "text": text(row["text"], 500), "expected": row["expected"]})
    if len({row["text"] for row in cases}) != len(cases):
        raise ValueError("Exact case texts repeat")
    positive = sum(row["expected"] == "ALLOW" for row in cases)
    negative = len(cases) - positive
    if positive < 2 or negative < 2:
        raise ValueError("Each class needs at least two cases")
    if spec["max_false_allows"] >= negative or spec["max_false_denies"] >= positive:
        raise ValueError("Error caps must reject constant predictors")
    return cases


def commitment(owner, contract_address, chain_id, spec, cases, salt):
    normalized = canonical_spec(spec)
    corpus = canonical_cases(cases, normalized)
    context = {"contract_address": address(contract_address), "chain_id": integer(chain_id, 1, (1 << 256) - 1)}
    payload = {"domain": DOMAIN, "context": context, "owner": address(owner), "spec": normalized,
               "cases": corpus, "salt": text(salt, 128, 16)}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    # Reads owner, contract_address, chain_id, spec, cases, salt from local stdin.
    # Only the digest is printed. Choose a fresh cryptographically random salt.
    print(commitment(**json.load(sys.stdin)))
