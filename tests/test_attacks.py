from poisonkit.attacks import ATTACKS, get_attack, list_attacks


def test_all_attacks_load():
    attacks = list_attacks()
    assert len(attacks) >= 5
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids)), "attack ids must be unique"


def test_tool_schemas_valid():
    for a in ATTACKS:
        assert a.tools, f"{a.id} has no tools"
        for t in a.tools:
            assert t.name and t.description and t.parameters.get("type") == "object"
            assert t.impl in {"static_text", "canary_record", "exfil_sink", "poisoned_docs"}


def test_get_attack_unknown():
    try:
        get_attack("nope")
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError")
