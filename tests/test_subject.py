# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

from gnap_caep_risc import person_from

CHECK = {
    "id_token_issuer": "https://as.example",
    "audiences": [],
    "clock_tolerance_sec": 0,
    "keys": lambda: [],
}


def test_uid_from_account_keeps_the_protocol_subject():
    person = person_from({
        "sub_ids": [
            {"format": "iss_sub", "iss": "https://as.example", "sub": "urn:uuid:abc"},
            {"format": "account", "uri": "acct:gnap-demo-user@localhost:8081"},
        ],
    }, CHECK)
    assert person.sub == "urn:uuid:abc"
    assert person.iss == "https://as.example"
    assert person.uid == "gnap-demo-user"


def test_percent_decodes_the_user_part_and_keeps_invalid_encoding():
    decoded = person_from({"sub_ids": [{"format": "account", "uri": "acct:ada%20lovelace@idp.example"}]}, CHECK)
    assert decoded.sub == "acct:ada%20lovelace@idp.example"
    assert decoded.uid == "ada lovelace"
    kept = person_from({"sub_ids": [{"format": "account", "uri": "acct:%E0%A4%A@idp.example"}]}, CHECK)
    assert kept.uid == "%E0%A4%A"


def test_uid_stays_unset_without_an_account_identifier():
    person = person_from({"sub_ids": [{"format": "iss_sub", "iss": "https://as.example", "sub": "urn:uuid:abc"}]}, CHECK)
    assert person.uid is None
    assert person.sub == "urn:uuid:abc"
