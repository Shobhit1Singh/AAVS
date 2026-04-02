from typing import Dict, Any, Set


class SemanticDiffEngine:

    # -------------------------------------------------------
    # Helpers
    # -------------------------------------------------------

    def _flatten_keys(self, obj, prefix="") -> Set[str]:
        keys = set()

        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.add(full)
                keys |= self._flatten_keys(v, full)

        elif isinstance(obj, list):
            for item in obj:
                keys |= self._flatten_keys(item, prefix)

        return keys

    # -------------------------------------------------------
    # Main Compare
    # -------------------------------------------------------

    def compare(self, base_response: Dict[str, Any], test_response: Dict[str, Any]):

        issues = []

        if not base_response or not test_response:
            return issues

        # ✅ Correct field usage
        base_text = base_response.get("response_body", "")
        test_text = test_response.get("response_body", "")

        base_status = base_response.get("status_code")
        test_status = test_response.get("status_code")

        base_json = base_response.get("json")
        test_json = test_response.get("json")

        # ---------------------------------------------------
        # 1️⃣ Relative Response Size Anomaly
        # ---------------------------------------------------

        if base_text:
            diff_ratio = abs(len(test_text) - len(base_text)) / max(len(base_text), 1)

            if diff_ratio > 0.3:
                issues.append({
                    "type": "Response Size Anomaly",
                    "detail": f"Size changed by {round(diff_ratio * 100, 2)}%"
                })

        # ---------------------------------------------------
        # 2️⃣ Status Code Intelligence
        # ---------------------------------------------------

        if base_status != test_status:
            issues.append({
                "type": "Status Code Change",
                "detail": f"{base_status} → {test_status}"
            })

            # 🔥 Auth bypass signal
            if base_status in [401, 403] and test_status == 200:
                issues.append({
                    "type": "Possible Authorization Bypass",
                    "detail": "Restricted endpoint became accessible"
                })

        # ---------------------------------------------------
        # 3️⃣ JSON Structure Diff (Deep)
        # ---------------------------------------------------

        if isinstance(base_json, dict) and isinstance(test_json, dict):

            base_keys = self._flatten_keys(base_json)
            test_keys = self._flatten_keys(test_json)

            new_keys = test_keys - base_keys
            removed_keys = base_keys - test_keys

            if new_keys:
                issues.append({
                    "type": "New Fields Exposed",
                    "detail": list(new_keys)
                })

            if removed_keys:
                issues.append({
                    "type": "Fields Missing",
                    "detail": list(removed_keys)
                })

            # ---------------------------------------------------
            # 4️⃣ Value / Type Changes
            # ---------------------------------------------------

            for key in base_json:

                if key in test_json:

                    base_val = base_json[key]
                    test_val = test_json[key]

                    # Type change
                    if type(base_val) != type(test_val):
                        issues.append({
                            "type": "Type Change Detected",
                            "detail": f"{key}: {type(base_val).__name__} → {type(test_val).__name__}"
                        })

                    # Suspicious expansion
                    elif isinstance(base_val, str) and isinstance(test_val, str):
                        if len(test_val) > len(base_val) * 2:
                            issues.append({
                                "type": "Suspicious Value Expansion",
                                "detail": f"{key} length increased significantly"
                            })

        # ---------------------------------------------------
        # 5️⃣ Sensitive Keyword Emergence
        # ---------------------------------------------------

        sensitive_keywords = ["admin", "token", "password", "secret", "key"]

        base_lower = base_text.lower()
        test_lower = test_text.lower()

        for word in sensitive_keywords:
            if word in test_lower and word not in base_lower:
                issues.append({
                    "type": "Sensitive Keyword Detected",
                    "detail": word
                })

        # ---------------------------------------------------
        # 6️⃣ Content Shift Detection (basic)
        # ---------------------------------------------------

        if base_text and test_text:

            base_words = set(base_text.split())
            test_words = set(test_text.split())

            new_words = test_words - base_words

            if len(new_words) > 20:
                issues.append({
                    "type": "Content Drift Detected",
                    "detail": f"{len(new_words)} new tokens introduced"
                })

        return issues