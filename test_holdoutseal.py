import copy
import hashlib
import json
import unittest

from commitment import commitment, canonical_spec, canonical_cases
from testsupport import load, UserError


A = "0x" + "1" * 40
B = "0x" + "2" * 40
C = "0x" + "3" * 40
D = "0x" + "4" * 40
E = "0x" + "5" * 40
SALT = "private-demo-salt-0123456789"


def fixture_spec(nonce="fixture"):
    return {"title": "Declared tool-policy holdout", "purpose": "Classify synthetic export permission cases.",
            "label_rule": "ALLOW means the policy permits the exact export; otherwise DENY or uncertainty.",
            "candidates": [A, B], "case_count": 4, "max_false_allows": 0, "max_false_denies": 0,
            "nonce": nonce, "enrollment_seconds": 60, "reveal_seconds": 60, "evaluation_seconds": 600}


def fixture_cases():
    return [{"case_id": i, "text": text, "expected": "ALLOW" if i < 2 else "DENY"}
            for i, text in enumerate(["Owner approved export A.", "Owner approved export B.",
                                      "Owner did not approve export C.", "Export D has expired approval."])]


class HoldoutTests(unittest.TestCase):
    def setUp(self):
        self.m, self.c, self.rt = load()
        self.nonce = 0

    def state(self):
        return copy.deepcopy((self.c.benchmarks, self.c.candidates, self.c.attempts, self.c.nonce_keys,
                              self.c.enrollment_keys, self.c.benchmark_count, self.c.candidate_count))

    def digest(self, spec, cases, salt=SALT, owner=A, address=None, chain_id=None):
        return commitment(owner, address or self.rt.contract_address, self.rt.chain_id if chain_id is None else chain_id,
                          spec, cases, salt)

    def opened(self, spec=None, cases=None, salt=SALT):
        self.nonce += 1
        spec = copy.deepcopy(spec or fixture_spec("fixture-%d" % self.nonce))
        cases = copy.deepcopy(cases or fixture_cases())
        bid = self.c.open_benchmark(json.dumps(spec, ensure_ascii=False), self.digest(spec, cases, salt))
        return bid, spec, cases

    def ready(self, spec=None, cases=None, policy="Allow an export only with current owner approval.", salt=SALT):
        bid, spec, cases = self.opened(spec, cases, salt)
        cid = self.c.enroll_policy(bid, policy)
        self.rt.clock = self.c.get_benchmark(bid)["record"]["enrollment_deadline"]
        self.c.reveal_benchmark(bid, json.dumps(cases, ensure_ascii=False), salt)
        self.rt.output = {"predictions": [{"case_id": r["case_id"], "outcome": r["expected"]} for r in cases]}
        return bid, cid, spec, cases

    def predictions(self, labels):
        self.rt.output = {"predictions": [{"case_id": i, "outcome": label} for i, label in enumerate(labels)]}

    def test_offline_commitment_matches_inline_function_and_independent_sha(self):
        spec, cases = fixture_spec(), fixture_cases()
        expected = self.m._commitment(self.m._context(), A, self.m._spec(spec), self.m._cases(cases, self.m._spec(spec)), SALT)
        self.assertEqual(self.digest(spec, cases), expected)
        payload = {"domain": self.m.DOMAIN, "context": self.m._context(), "owner": A,
                   "spec": canonical_spec(spec), "cases": canonical_cases(cases, canonical_spec(spec)), "salt": SALT}
        direct = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        self.assertEqual(expected, direct)

    def test_commitment_canonicalizes_json_key_order_but_preserves_exact_unicode_text(self):
        spec, cases = fixture_spec(), fixture_cases()
        spec["purpose"] = "Line one\nUnicode 🧪 and \"quotes\"."
        cases[0]["text"] = "Café e\u0301 🧪\nquoted \"case\""
        shuffled_spec = dict(reversed(list(spec.items())))
        shuffled_cases = [dict(reversed(list(row.items()))) for row in cases]
        self.assertEqual(self.digest(spec, cases), self.digest(shuffled_spec, shuffled_cases))
        altered = copy.deepcopy(cases)
        altered[0]["text"] += " "
        self.assertNotEqual(self.digest(spec, cases), self.digest(spec, altered))

    def test_commitment_binds_owner_deployment_chain_nonce_thresholds_cases_and_salt(self):
        spec, cases = fixture_spec(), fixture_cases()
        original = self.digest(spec, cases)
        alternatives = [self.digest(spec, cases, owner=B), self.digest(spec, cases, address=B),
                        self.digest(spec, cases, chain_id=123), self.digest(spec, cases, salt=SALT + "x")]
        for field, value in [("nonce", "different"), ("max_false_allows", 1), ("evaluation_seconds", 601)]:
            changed = dict(spec)
            changed[field] = value
            alternatives.append(self.digest(changed, cases))
        changed = copy.deepcopy(cases)
        changed[0]["text"] += " Extra context."
        alternatives.append(self.digest(spec, changed))
        self.assertTrue(all(value != original for value in alternatives))

    def test_open_locks_spec_and_absolute_stage_deadlines_without_model(self):
        before = self.rt.clock
        bid, spec, _ = self.opened()
        record = self.c.get_benchmark(bid)["record"]
        self.assertEqual(record["spec"], self.m._spec(spec))
        self.assertEqual([record[k] for k in ["enrollment_deadline", "reveal_deadline", "evaluation_deadline"]],
                         [before + 60, before + 120, before + 720])
        self.assertEqual(record["context"], self.m._context())
        self.assertEqual(record["status"], "COMMITTED")
        self.assertIsNone(record["cases"])
        self.assertEqual(self.rt.calls, 0)

    def test_owner_nonce_cannot_open_another_copy(self):
        bid, spec, cases = self.opened()
        before = self.state()
        with self.assertRaisesRegex(UserError, "nonce"):
            self.c.open_benchmark(json.dumps(spec), self.digest(spec, cases))
        self.assertEqual(self.state(), before)

    def test_enrollment_is_fixed_roster_one_policy_per_address(self):
        bid, _, _ = self.opened()
        self.rt.as_sender(C)
        with self.assertRaises(UserError):
            self.c.enroll_policy(bid, "A policy.")
        self.rt.as_sender(A)
        cid = self.c.enroll_policy(bid, "The exact first policy.")
        before = self.state()
        with self.assertRaises(UserError):
            self.c.enroll_policy(bid, "A replacement policy.")
        self.assertEqual(self.state(), before)
        self.assertEqual(self.c.get_candidate(cid)["record"]["locked"]["policy"], "The exact first policy.")

    def test_stage_cutoffs_prevent_early_reveal_and_late_enrollment(self):
        bid, _, cases = self.opened()
        self.c.enroll_policy(bid, "The fixed policy.")
        deadline = self.c.get_benchmark(bid)["record"]["enrollment_deadline"]
        self.rt.clock = deadline - 1
        before = self.state()
        with self.assertRaises(UserError):
            self.c.reveal_benchmark(bid, json.dumps(cases), SALT)
        self.assertEqual(self.state(), before)
        self.rt.clock = deadline
        self.rt.as_sender(B)
        with self.assertRaises(UserError):
            self.c.enroll_policy(bid, "Too late.")
        self.rt.as_sender(A)
        self.c.reveal_benchmark(bid, json.dumps(cases), SALT)
        self.assertEqual(self.c.get_benchmark(bid)["record"]["status"], "REVEALED")

    def test_reveal_is_owner_only_and_wrong_salt_does_not_consume_it(self):
        bid, _, cases = self.opened()
        self.c.enroll_policy(bid, "A policy.")
        self.rt.clock += 60
        before = self.state()
        self.rt.as_sender(B)
        with self.assertRaises(UserError):
            self.c.reveal_benchmark(bid, json.dumps(cases), SALT)
        self.rt.as_sender(A)
        with self.assertRaisesRegex(UserError, "committed"):
            self.c.reveal_benchmark(bid, json.dumps(cases), SALT + "wrong")
        self.assertEqual(self.state(), before)
        self.c.reveal_benchmark(bid, json.dumps(cases), SALT)

    def test_reveal_is_once_and_never_reopens_enrollment(self):
        bid, cid, _, cases = self.ready()
        before = self.state()
        for call in [lambda: self.c.reveal_benchmark(bid, json.dumps(cases), SALT),
                     lambda: self.c.enroll_policy(bid, "A new policy.")]:
            with self.assertRaises(UserError):
                call()
        self.assertEqual(self.state(), before)
        self.assertEqual(self.c.get_candidate(cid)["record"]["status"], "ENROLLED")

    def test_modified_case_or_reference_label_cannot_match_commitment(self):
        bid, _, cases = self.opened()
        self.c.enroll_policy(bid, "Policy.")
        self.rt.clock += 60
        for variant in ["text", "labels"]:
            changed = copy.deepcopy(cases)
            if variant == "text":
                changed[0]["text"] += " changed"
            else:
                changed[0]["expected"], changed[2]["expected"] = changed[2]["expected"], changed[0]["expected"]
            before = self.state()
            with self.assertRaisesRegex(UserError, "committed"):
                self.c.reveal_benchmark(bid, json.dumps(changed), SALT)
            self.assertEqual(self.state(), before)

    def test_case_schema_requires_complete_order_and_strict_integer_ids(self):
        spec, cases = fixture_spec(), fixture_cases()
        variants = [cases[:-1], list(reversed(cases))]
        for value in [True, 0.0, -1, "0"]:
            changed = copy.deepcopy(cases)
            changed[0]["case_id"] = value
            variants.append(changed)
        changed = copy.deepcopy(cases)
        changed[0]["summary"] = "extra"
        variants.append(changed)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(UserError):
                self.m._cases(value, spec)

    def test_duplicate_exact_case_text_is_rejected(self):
        cases = fixture_cases()
        cases[1]["text"] = cases[0]["text"]
        with self.assertRaisesRegex(UserError, "distinct"):
            self.m._cases(cases, fixture_spec())

    def test_class_representation_and_caps_reject_constant_predictors(self):
        cases = fixture_cases()
        cases[1]["expected"] = "DENY"
        with self.assertRaisesRegex(UserError, "two reference"):
            self.m._cases(cases, fixture_spec())
        for field in ["max_false_allows", "max_false_denies"]:
            spec = fixture_spec()
            spec[field] = 2
            with self.assertRaisesRegex(UserError, "constant"):
                self.m._cases(fixture_cases(), spec)

    def test_unrevealed_corpus_cannot_be_assessed(self):
        bid, _, _ = self.opened()
        cid = self.c.enroll_policy(bid, "Policy.")
        before = self.state()
        with self.assertRaises(UserError):
            self.c.assess_policy(cid)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.rt.calls, 0)

    def test_success_scores_complete_corpus_and_creates_exact_scoped_certificate(self):
        bid, cid, _, cases = self.ready()
        receipt = self.c.assess_policy(cid)
        self.assertEqual(receipt["decision"], "CERTIFIED")
        self.assertEqual(receipt["metrics"], {"confusion": {"true_allow": 2, "false_allow": 0, "true_deny": 2, "false_deny": 0},
                                               "case_count": 4, "correct_count": 4, "accuracy_bps": 10000})
        candidate = self.c.get_candidate(cid)["record"]
        certificate = self.c.get_certificate(cid)
        self.assertEqual(certificate["payload"], receipt["certificate_payload"])
        self.assertEqual(certificate["receipt_hash"], self.m._hash(self.m._json(receipt)))
        self.assertEqual(certificate["payload"]["scope"], "EXACT_OWNER_DECLARED_BENCHMARK_ONLY")
        self.assertEqual(candidate["status"], "CERTIFIED")
        self.assertEqual(receipt["input"]["benchmark"]["cases"], cases)
        self.assertEqual(self.c.get_attempt(cid, 1), receipt)

    def test_false_allow_is_not_hidden_by_overall_accuracy(self):
        _, cid, _, _ = self.ready()
        self.predictions(["ALLOW", "ALLOW", "ALLOW", "DENY"])
        receipt = self.c.assess_policy(cid)
        self.assertEqual(receipt["decision"], "FAILED")
        self.assertEqual(receipt["metrics"]["confusion"]["false_allow"], 1)
        self.assertEqual(receipt["metrics"]["accuracy_bps"], 7500)
        with self.assertRaises(UserError):
            self.c.get_certificate(cid)

    def test_false_deny_is_counted_separately(self):
        _, cid, _, _ = self.ready()
        self.predictions(["DENY", "ALLOW", "DENY", "DENY"])
        receipt = self.c.assess_policy(cid)
        self.assertEqual(receipt["decision"], "FAILED")
        self.assertEqual(receipt["metrics"]["confusion"]["false_deny"], 1)

    def test_frozen_error_caps_are_applied_to_both_directions(self):
        spec = fixture_spec()
        spec.update({"max_false_allows": 1, "max_false_denies": 1})
        _, cid, _, _ = self.ready(spec=spec)
        self.predictions(["DENY", "ALLOW", "ALLOW", "DENY"])
        receipt = self.c.assess_policy(cid)
        self.assertTrue(receipt["certified"])
        self.assertEqual(receipt["metrics"]["accuracy_bps"], 5000)

    def test_any_uncertainty_is_terminal_and_never_partially_scored(self):
        _, cid, _, _ = self.ready()
        self.predictions(["ALLOW", "UNCERTAIN", "DENY", "DENY"])
        receipt = self.c.assess_policy(cid)
        self.assertEqual(receipt["decision"], "INCONCLUSIVE")
        self.assertIsNone(receipt["metrics"])
        self.assertIsNone(receipt["certificate_payload"])
        self.assertFalse(receipt["certified"])
        before = self.state()
        self.predictions(["ALLOW", "ALLOW", "DENY", "DENY"])
        with self.assertRaises(UserError):
            self.c.assess_policy(cid)
        self.assertEqual(self.state(), before)

    def test_failed_or_certified_candidate_cannot_shop_for_a_new_verdict(self):
        for labels in [["ALLOW"] * 4, ["ALLOW", "ALLOW", "DENY", "DENY"]]:
            _, cid, _, _ = self.ready()
            self.predictions(labels)
            self.c.assess_policy(cid)
            before = self.state()
            with self.assertRaises(UserError):
                self.c.assess_policy(cid)
            self.assertEqual(self.state(), before)

    def test_only_candidate_can_spend_technical_assessment_attempts(self):
        _, cid, _, _ = self.ready()
        self.rt.as_sender(B)
        before = self.state()
        with self.assertRaises(UserError):
            self.c.assess_policy(cid)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.rt.calls, 0)

    def test_technical_failures_have_three_stored_attempts_and_no_certificate(self):
        _, cid, _, _ = self.ready()
        self.rt.output = RuntimeError("temporary")
        for attempt in range(1, 4):
            receipt = self.c.assess_policy(cid)
            self.assertEqual(receipt["decision"], "UNRESOLVED")
            self.assertEqual(self.c.get_attempt(cid, attempt), receipt)
            self.assertFalse(receipt["inspection"]["semantic_complete"])
        self.assertEqual(self.c.get_candidate(cid)["record"]["status"], "UNRESOLVED_FINAL")
        with self.assertRaises(UserError):
            self.c.assess_policy(cid)

    def test_malformed_predictions_do_not_create_partial_scores(self):
        bad = [None, [], {"predictions": []}, {"predictions": [{"case_id": i, "outcome": "ALLOW"} for i in range(3)]},
               {"predictions": [{"case_id": i, "outcome": "MAYBE"} for i in range(4)]},
               {"predictions": [{"case_id": True if i == 0 else i, "outcome": "ALLOW"} for i in range(4)]},
               {"predictions": [{"case_id": i, "outcome": "ALLOW", "reason": "extra"} for i in range(4)]}]
        for output in bad:
            with self.subTest(output=output):
                _, cid, _, _ = self.ready()
                self.rt.output = output
                receipt = self.c.assess_policy(cid)
                self.assertEqual(receipt["decision"], "UNRESOLVED")
                self.assertIsNone(receipt["metrics"])

    def test_independent_disagreement_cannot_persist_a_leader_result(self):
        _, cid, _, _ = self.ready()
        self.rt.validator_output = {"predictions": [{"case_id": i, "outcome": "UNCERTAIN"} for i in range(4)]}
        before = self.state()
        with self.assertRaises(AssertionError):
            self.c.assess_policy(cid)
        self.assertEqual(self.state(), before)

    def test_every_complete_receipt_leaf_and_missing_extra_payload_are_bound(self):
        _, cid, _, _ = self.ready()
        candidate = self.c.get_candidate(cid)["record"]
        benchmark = self.c.get_benchmark(candidate["locked"]["benchmark_id"])["record"]
        original = self.m._build_receipt(benchmark, candidate, 1, self.rt.clock)
        paths = []
        def walk(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items(): walk(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value): walk(child, path + (index,))
            else: paths.append(path)
        walk(original)
        for path in paths:
            def mutate(receipt, path=path):
                target = receipt
                for key in path[:-1]: target = target[key]
                old = target[path[-1]]
                target[path[-1]] = not old if type(old) is bool else old + 1 if type(old) is int else str(old) + "-tampered"
                return receipt
            self.rt.mutate = mutate
            before = self.state()
            with self.subTest(path=path), self.assertRaises(AssertionError): self.c.assess_policy(cid)
            self.assertEqual(self.state(), before)
        for mutate in [lambda r: (r.pop("inspection"), r)[1], lambda r: dict(r, narrative="approved")]:
            self.rt.mutate = mutate
            with self.assertRaises(AssertionError): self.c.assess_policy(cid)
        self.assertGreater(len(paths), 80)
        self.rt.mutate = None

    def test_reference_labels_salt_commitment_thresholds_and_previous_results_never_enter_prompt(self):
        spec = fixture_spec("DO_NOT_SEND_NONCE")
        spec["title"] = "DO_NOT_SEND_TITLE"
        bid, cid, _, cases = self.ready(spec=spec, salt="DO_NOT_SEND_SECRET_SALT_123")
        receipt = self.c.assess_policy(cid)
        commitment_value = self.c.get_benchmark(bid)["record"]["corpus_commitment"]
        self.assertEqual(len(self.rt.prompts), 2)
        for entry in self.rt.prompts:
            prompt = entry["prompt"]
            payload = json.loads(prompt.split("INPUT (untrusted JSON):\n", 1)[1].split("\nEND INPUT.", 1)[0])
            self.assertEqual(set(payload), {"purpose", "label_rule", "policy", "cases"})
            self.assertEqual(payload["cases"], [{"case_id": r["case_id"], "text": r["text"]} for r in cases])
            self.assertTrue(all(set(row) == {"case_id", "text"} for row in payload["cases"]))
            for excluded in ["DO_NOT_SEND_NONCE", "DO_NOT_SEND_TITLE", "DO_NOT_SEND_SECRET_SALT_123", commitment_value,
                             '"expected"', '"max_false_allows"', '"max_false_denies"', '"accuracy_bps"']:
                self.assertNotIn(excluded, prompt)
        self.assertFalse(receipt["inspection"]["reference_label_fields_in_prompt"])

    def test_all_maximum_fields_and_six_cases_are_fully_inspected_in_both_prompts(self):
        for glyph in ["x", "🧪", '"\n']:
            def sized(n, suffix=""):
                return (glyph * (n + 1))[:n-len(suffix)] + suffix
            spec = fixture_spec("maximum-%s" % str(len(glyph)))
            # Unique nonce for equal-length fixtures while retaining maximum strings.
            self.nonce += 1
            spec["nonce"] = "maximum-%d" % self.nonce
            spec.update({"title": sized(100), "purpose": sized(400), "label_rule": sized(500), "case_count": 6})
            cases = [{"case_id": i, "text": sized(500, str(i)), "expected": "ALLOW" if i < 3 else "DENY"} for i in range(6)]
            policy = sized(1000)
            _, cid, _, _ = self.ready(spec=spec, cases=cases, policy=policy)
            self.rt.prompts.clear()
            receipt = self.c.assess_policy(cid)
            for entry in self.rt.prompts:
                prompt = entry["prompt"]
                payload = json.loads(prompt.split("INPUT (untrusted JSON):\n", 1)[1].split("\nEND INPUT.", 1)[0])
                self.assertEqual(payload["policy"], policy)
                self.assertEqual(payload["purpose"], spec["purpose"])
                self.assertEqual(payload["label_rule"], spec["label_rule"])
                self.assertEqual([r["text"] for r in payload["cases"]], [r["text"] for r in cases])
                self.assertLessEqual(len(prompt), self.m.MAX_PROMPT_CHARS)
                self.assertLessEqual(len(prompt.encode("utf-8")), self.m.MAX_PROMPT_BYTES)
            self.assertFalse(receipt["inspection"]["prompt_truncated"])

    def test_budget_rejection_does_not_reveal_partial_corpus_or_advance_clock_floor(self):
        for limit in ["MAX_PROMPT_CHARS", "MAX_PROMPT_BYTES"]:
            bid, _, cases = self.opened()
            self.c.enroll_policy(bid, "Policy.")
            self.rt.clock += 60
            before = self.state()
            old = getattr(self.m, limit)
            setattr(self.m, limit, 10)
            with self.assertRaisesRegex(UserError, "inspection budget"):
                self.c.reveal_benchmark(bid, json.dumps(cases), SALT)
            self.assertEqual(self.state(), before)
            setattr(self.m, limit, old)

    def test_maximum_emoji_fields_work_through_default_escaped_json_transport(self):
        spec = fixture_spec("🧪" * 80)
        spec.update({"title": "🧪" * 100, "purpose": "🧪" * 400, "label_rule": "🧪" * 500, "case_count": 6})
        cases = [{"case_id": i, "text": "🧪" * 499 + str(i), "expected": "ALLOW" if i < 3 else "DENY"} for i in range(6)]
        encoded_spec, encoded_cases = json.dumps(spec), json.dumps(cases)
        self.assertGreater(len(encoded_spec), 12000)
        self.assertGreater(len(encoded_cases), 24000)
        bid = self.c.open_benchmark(encoded_spec, self.digest(spec, cases))
        cid = self.c.enroll_policy(bid, "🧪" * 1000)
        self.rt.clock += 60
        self.c.reveal_benchmark(bid, encoded_cases, SALT)
        self.rt.output = {"predictions": [{"case_id": r["case_id"], "outcome": r["expected"]} for r in cases]}
        receipt = self.c.assess_policy(cid)
        self.assertEqual(receipt["decision"], "CERTIFIED")
        self.assertEqual(len(self.rt.prompts), 2)
        for entry in self.rt.prompts:
            payload = json.loads(entry["prompt"].split("INPUT (untrusted JSON):\n", 1)[1].split("\nEND INPUT.", 1)[0])
            self.assertEqual(payload["policy"], "🧪" * 1000)
            self.assertEqual([r["text"] for r in payload["cases"]], [r["text"] for r in cases])
        self.assertFalse(receipt["inspection"]["prompt_truncated"])

    def test_impossible_public_error_caps_are_rejected_before_any_storage(self):
        spec = fixture_spec()
        spec.update({"max_false_allows": 2, "max_false_denies": 2})
        before = self.state()
        with self.assertRaisesRegex(UserError, "no legal"):
            self.c.open_benchmark(json.dumps(spec), "0" * 64)
        self.assertEqual(self.state(), before)
        with self.assertRaisesRegex(ValueError, "no legal"):
            self.digest(spec, fixture_cases())

    def test_assessment_deadline_is_exclusive_and_permissionless_expiry_creates_no_score(self):
        bid, cid, _, _ = self.ready()
        self.rt.clock = self.c.get_benchmark(bid)["record"]["evaluation_deadline"]
        with self.assertRaises(UserError): self.c.assess_policy(cid)
        self.rt.as_sender(E)
        self.assertEqual(self.c.finalize_expired(bid), 1)
        candidate = self.c.get_candidate(cid)["record"]
        self.assertEqual(candidate["status"], "EXPIRED")
        self.assertIsNone(candidate["receipt"])
        self.assertIsNone(candidate["certificate"])

    def test_missing_reveal_expires_enrolled_candidates_without_model(self):
        bid, _, cases = self.opened()
        cid = self.c.enroll_policy(bid, "Policy.")
        self.rt.clock = self.c.get_benchmark(bid)["record"]["reveal_deadline"]
        before = self.state()
        with self.assertRaises(UserError): self.c.reveal_benchmark(bid, json.dumps(cases), SALT)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.c.finalize_expired(bid), 1)
        self.assertEqual(self.c.get_benchmark(bid)["record"]["status"], "EXPIRED")
        self.assertEqual(self.c.get_candidate(cid)["record"]["status"], "EXPIRED")
        self.assertEqual(self.rt.calls, 0)
        with self.assertRaises(UserError): self.c.finalize_expired(bid)

    def test_completed_certificate_survives_round_finalization_as_scoped_history(self):
        bid, cid, _, _ = self.ready()
        self.c.assess_policy(cid)
        certificate = self.c.get_certificate(cid)
        self.rt.clock = self.c.get_benchmark(bid)["record"]["evaluation_deadline"]
        self.assertEqual(self.c.finalize_expired(bid), 0)
        self.assertEqual(self.c.get_certificate(cid), certificate)
        self.assertEqual(self.c.get_benchmark(bid)["record"]["status"], "FINALIZED")

    def test_expiry_views_preview_without_mutating_records(self):
        bid, cid, _, _ = self.ready()
        self.rt.clock = self.c.get_benchmark(bid)["record"]["evaluation_deadline"]
        before = self.state()
        self.assertEqual(self.c.get_benchmark(bid)["effective_status"], "FINALIZED")
        self.assertEqual(self.c.get_candidate(cid)["effective_status"], "EXPIRED")
        self.assertEqual(self.state(), before)

    def test_backwards_time_rejects_without_changing_results_or_candidates(self):
        bid, cid, _, _ = self.ready()
        self.rt.clock += 5
        self.c.assess_policy(cid)
        before = self.state()
        self.rt.clock -= 1
        for call in [lambda: self.c.get_benchmark(bid), lambda: self.c.finalize_expired(bid), lambda: self.c.assess_policy(cid)]:
            with self.assertRaisesRegex(UserError, "time moved backward"): call()
        self.assertEqual(self.state(), before)
        # Immutable completed certificate remains readable as history.
        self.assertIsNotNone(self.c.get_certificate(cid))

    def test_bad_spec_addresses_boolean_counts_text_and_ids_fail_before_writes(self):
        variants = []
        for field, value in [("case_count", True), ("enrollment_seconds", False), ("evaluation_seconds", 59),
                             ("candidates", [A, A]), ("candidates", ["0x" + "0" * 40]),
                             ("title", " "), ("purpose", "\ud800"), ("max_false_allows", -1)]:
            spec = fixture_spec()
            spec[field] = value
            variants.append(spec)
        spec = fixture_spec()
        spec["extra"] = "unbound"
        variants.append(spec)
        for value in variants:
            before = self.state()
            with self.subTest(value=value), self.assertRaises(UserError):
                self.c.open_benchmark(json.dumps(value), "0" * 64)
            self.assertEqual(self.state(), before)
        for value in [True, -1, 0.0, "0"]:
            with self.assertRaises(UserError): self.c.get_benchmark(value)
        self.assertEqual(self.rt.calls, 0)

    def test_all_four_roster_slots_are_bounded_and_pending_finalization_preserves_completed(self):
        spec = fixture_spec()
        spec["candidates"] = [A, B, C, D]
        bid, _, cases = self.opened(spec=spec)
        ids = []
        for address in spec["candidates"]:
            self.rt.as_sender(address)
            ids.append(self.c.enroll_policy(bid, "Policy for " + address))
        self.rt.as_sender(A)
        self.rt.clock += 60
        self.c.reveal_benchmark(bid, json.dumps(cases), SALT)
        self.c.assess_policy(ids[0])
        self.rt.clock = self.c.get_benchmark(bid)["record"]["evaluation_deadline"]
        self.assertEqual(self.c.finalize_expired(bid), 3)
        self.assertEqual([self.c.get_candidate(i)["record"]["status"] for i in ids], ["CERTIFIED", "EXPIRED", "EXPIRED", "EXPIRED"])

    def test_reveal_without_enrolled_candidate_is_rejected(self):
        bid, _, cases = self.opened()
        self.rt.clock += 60
        before = self.state()
        with self.assertRaises(UserError): self.c.reveal_benchmark(bid, json.dumps(cases), SALT)
        self.assertEqual(self.state(), before)

    def test_cross_deployment_or_chain_commitment_cannot_be_revealed_here(self):
        for digest in [self.digest(fixture_spec(), fixture_cases(), address=B),
                       self.digest(fixture_spec(), fixture_cases(), chain_id=123)]:
            self.m, self.c, self.rt = load()
            bid = self.c.open_benchmark(json.dumps(fixture_spec()), digest)
            self.c.enroll_policy(bid, "Policy.")
            self.rt.clock += 60
            with self.assertRaisesRegex(UserError, "committed"):
                self.c.reveal_benchmark(bid, json.dumps(fixture_cases()), SALT)

    def test_short_salt_cannot_be_committed_or_revealed(self):
        with self.assertRaises(ValueError): self.digest(fixture_spec(), fixture_cases(), salt="short")
        bid, _, cases = self.opened()
        self.c.enroll_policy(bid, "Policy.")
        self.rt.clock += 60
        before = self.state()
        with self.assertRaisesRegex(UserError, "Salt"):
            self.c.reveal_benchmark(bid, json.dumps(cases), "short")
        self.assertEqual(self.state(), before)

    def test_actual_clock_helper_is_outside_both_model_callbacks(self):
        _, cid, _, _ = self.ready()
        self.c.assess_policy(cid)
        self.assertGreater(self.rt.clock_reads, 0)
        self.assertFalse(self.rt.in_nondet)
        with self.assertRaisesRegex(AssertionError, "clock may not be read"):
            self.rt.run(lambda: self.m._now(), lambda result: True)


if __name__ == "__main__":
    unittest.main()
