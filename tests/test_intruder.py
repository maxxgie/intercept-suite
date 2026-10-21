"""Tests for the Intruder: attack types, generators, rules and grepping."""

from __future__ import annotations

import asyncio
import base64
import hashlib

from intercept.core.models import Request
from intercept.tools.generators import Generator, ProcessingRule, apply_rules


def _request(url: str = "http://127.0.0.1/x?a=§a§&b=§b§") -> Request:
    return Request(method="GET", url=url)


# ------------------------------------------------------------ attack types


def test_a_sniper_tries_one_position_at_a_time(app):
    """A sniper works on one position, the others are left empty."""
    request = _request()
    job = app.fuzzer.create_job(request, ["one", "two"], attack_type="sniper")
    assert job.total == 4

    combinations = job.combinations()
    assert len(combinations) == 4
    for positions, payloads in combinations:
        assert len(positions) == 1
        assert len(payloads) == 1
    assert [positions[0].name for positions, _ in combinations] == ["a", "a", "b", "b"]


def test_a_sniper_leaves_the_other_positions_empty(app):
    """The positions the sniper is not working on are blank."""
    from intercept.tools.fuzzer import _apply_many

    job = app.fuzzer.create_job(_request(), ["one"], attack_type="sniper")
    positions, payloads = job.combinations()[0]
    request = _apply_many(job.template, list(zip(positions, payloads, strict=False)))
    assert "a=one" in request.url
    assert "§b§" not in request.url
    assert "b=&" in request.url or request.url.endswith("b=")


def test_a_battering_ram_puts_one_payload_in_every_position(app):
    """A battering ram sends the same payload everywhere at once."""
    job = app.fuzzer.create_job(_request(), ["one", "two"], attack_type="battering-ram")
    assert job.total == 2
    combinations = job.combinations()
    for positions, payloads in combinations:
        assert len(positions) == 2
        assert payloads[0] == payloads[1]


def test_a_pitchfork_walks_the_positions_together(app):
    """A pitchfork sends one payload of each list at the same time."""
    job = app.fuzzer.create_job(
        _request(),
        attack_type="pitchfork",
        payload_sets=[["a1", "a2"], ["b1", "b2"]],
    )
    assert job.total == 2
    combinations = job.combinations()
    assert [payloads for _positions, payloads in combinations] == [
        ["a1", "b1"],
        ["a2", "b2"],
    ]


def test_a_cluster_bomb_tries_every_combination(app):
    """A cluster bomb tries every combination of the payload lists."""
    job = app.fuzzer.create_job(
        _request(),
        attack_type="cluster-bomb",
        payload_sets=[["a1", "a2"], ["b1", "b2"]],
    )
    assert job.total == 4
    combinations = job.combinations()
    assert sorted(payloads for _positions, payloads in combinations) == [
        ["a1", "b1"],
        ["a1", "b2"],
        ["a2", "b1"],
        ["a2", "b2"],
    ]


def test_an_unknown_attack_type_falls_back_to_the_sniper(app):
    """A name that is not known does not break the run."""
    job = app.fuzzer.create_job(_request(), ["one"], attack_type="nonsense")
    assert job.attack_type == "sniper"


# ------------------------------------------------------------- generators


def test_the_number_generator_counts():
    """The number generator produces a range of numbers."""
    payloads = Generator("numbers", {"start": 1, "end": 5}).generate()
    assert payloads == ["1", "2", "3", "4", "5"]

    payloads = Generator("numbers", {"start": 10, "count": 3, "step": 5}).generate()
    assert payloads == ["10", "15", "20"]


def test_the_date_generator_walks_forward():
    """The date generator produces a series of dates."""
    payloads = Generator(
        "dates", {"start": "2024-01-01", "count": 3, "step": 1, "unit": "days"}
    ).generate()
    assert payloads == ["2024-01-01", "2024-01-02", "2024-01-03"]

    payloads = Generator(
        "dates", {"start": "2024-01-31", "count": 2, "step": 1, "unit": "months"}
    ).generate()
    assert payloads == ["2024-01-31", "2024-02-29"]


def test_the_brute_force_generator_covers_the_alphabet():
    """The brute force generator walks a character set."""
    payloads = Generator("bruteforce", {"charset": "ab", "length": 2}).generate()
    assert payloads == ["aa", "ab", "ba", "bb"]


def test_the_substitution_generator_replaces_one_thing_at_a_time():
    """The substitution generator starts from a base string."""
    payloads = Generator(
        "substitution", {"base": "abc", "substitutions": ["a=x", "b=y"]}
    ).generate()
    assert payloads == ["abc", "xbc", "ayc"]


def test_the_grep_generator_reads_a_directory(tmp_path):
    """The grep generator looks through a directory for a pattern."""
    (tmp_path / "a.txt").write_text("nothing here\nthe needle is here\n")
    (tmp_path / "b.txt").write_text("nothing\n")

    payloads = Generator("grep", {"path": str(tmp_path), "pattern": "needle"}).generate()
    assert len(payloads) == 1
    assert "the needle is here" in payloads[0]
    assert "a.txt" in payloads[0]


def test_the_file_generator_reads_a_wordlist(tmp_path):
    """The file generator reads the lines of a file."""
    path = tmp_path / "words.txt"
    path.write_text("admin\nroot\n\n")
    payloads = Generator("file", {"path": str(path)}).generate()
    assert payloads == ["admin", "root"]


def test_the_file_generator_says_nothing_when_the_file_is_missing(tmp_path):
    """A file that is not there gives no payloads instead of an error."""
    payloads = Generator("file", {"path": str(tmp_path / "nope.txt")}).generate()
    assert payloads == []


def test_the_custom_generator_fills_a_template():
    """The custom generator fills the placeholders of a template."""
    payloads = Generator("custom", {"template": "§a§§0§", "charset": "abc", "count": 3}).generate()
    assert payloads == ["a0", "b1", "c2"]


# ------------------------------------------------------------------ rules


def test_the_url_encoding_rule_escapes_the_payload():
    """The URL rule escapes the characters that would break the request."""
    assert ProcessingRule("url-encode").apply("a b&c") == "a%20b%26c"
    assert ProcessingRule("url-encode", {"form": True}).apply("a b") == "a+b"


def test_the_base64_rule_encodes_the_payload():
    """The base64 rule encodes the payload."""
    assert ProcessingRule("base64").apply("hello") == base64.b64encode(b"hello").decode()


def test_the_hash_rule_digests_the_payload():
    """The hash rule hashes the payload with the chosen algorithm."""
    assert ProcessingRule("hash", {"algorithm": "md5"}).apply("hello") == (
        hashlib.md5(b"hello").hexdigest()
    )
    assert ProcessingRule("hash", {"algorithm": "sha256"}).apply("hello") == (
        hashlib.sha256(b"hello").hexdigest()
    )


def test_the_prefix_and_suffix_rules_wrap_the_payload():
    """The prefix and suffix rules put text around the payload."""
    assert ProcessingRule("prefix", {"text": "<<"}).apply("x") == "<<x"
    assert ProcessingRule("suffix", {"text": ">>"}).apply("x") == "x>>"


def test_the_replace_rule_rewrites_the_payload():
    """The replace rule swaps one pattern for another."""
    rule = ProcessingRule("replace", {"pattern": "a", "replacement": "b"})
    assert rule.apply("banana") == "bbnbnb"


def test_the_extract_rule_keeps_the_matching_part():
    """The extract rule keeps what the pattern matched."""
    rule = ProcessingRule("extract", {"pattern": r"id=(\d+)"})
    assert rule.apply("id=42 rest") == "id=42"
    assert rule.apply("nothing") == ""


def test_a_broken_pattern_leaves_the_payload_alone():
    """A pattern that does not compile must not break the run."""
    rule = ProcessingRule("replace", {"pattern": "([", "replacement": "x"})
    assert rule.apply("value") == "value"


def test_the_rules_are_applied_in_order():
    """Every rule rewrites what the one before it produced."""
    payloads = apply_rules(
        ["a"],
        [
            ProcessingRule("base64"),
            ProcessingRule("prefix", {"text": "x"}),
        ],
    )
    assert payloads == ["x" + base64.b64encode(b"a").decode()]


async def test_the_rules_reach_the_request_that_is_sent(app, origin_url):
    """A rule is applied to the payload that goes on the wire."""
    request = Request(method="GET", url=f"{origin_url}/ruled?q=§q§")
    job = app.fuzzer.create_job(
        request,
        ["one"],
        attack_type="sniper",
        rules=[ProcessingRule("prefix", {"text": "pre-"})],
    )
    await app.fuzzer.run(job.id)

    assert job.results[0].payload == "pre-one"
    assert "q=pre-one" in job.results[0].url


# ------------------------------------------------------------------ grep


async def test_a_grep_match_marks_the_answer_as_a_hit(app, origin_url):
    """A response that holds the string is a hit."""
    request = Request(method="GET", url=f"{origin_url}/grep?q=§q§")
    job = app.fuzzer.create_job(
        request, ["found", "other"], attack_type="sniper", grep_match="found"
    )
    await app.fuzzer.run(job.id)

    hits = [result for result in job.results if result.hit]
    assert len(hits) == 1
    assert hits[0].payload == "found"
    assert hits[0].interesting is True


async def test_a_grep_extract_takes_the_match_out_of_the_answer(app, origin_url):
    """The pattern that matched is kept with the result."""
    request = Request(method="GET", url=f"{origin_url}/extract?q=§q§")
    job = app.fuzzer.create_job(
        request, ["one"], attack_type="sniper", grep_extract=r'"path":\s*"([^"]+)"'
    )
    await app.fuzzer.run(job.id)

    result = job.results[0]
    assert result.hit is True
    assert "/extract" in result.extracted


async def test_a_grep_that_matches_nothing_is_not_a_hit(app, origin_url):
    """A response without the string is not a hit."""
    request = Request(method="GET", url=f"{origin_url}/nogrep?q=§q§")
    job = app.fuzzer.create_job(
        request, ["one"], attack_type="sniper", grep_match="not-in-the-answer"
    )
    await app.fuzzer.run(job.id)

    assert job.results[0].hit is False


# ------------------------------------------------------------------- api


async def test_the_api_lists_the_generators_and_the_rules(client):
    """The interface can ask what the Intruder knows."""
    response = await client.get("/api/fuzz/generators")
    assert response.status_code == 200
    body = response.json()
    assert "numbers" in body["generators"]
    assert "bruteforce" in body["generators"]
    assert "base64" in body["rules"]
    assert "cluster-bomb" in body["attack_types"]


async def test_the_api_generates_the_payloads(client):
    """The interface can ask for the payloads of a generator."""
    response = await client.post(
        "/api/fuzz/payloads",
        json={
            "generator": {"kind": "numbers", "options": {"start": 1, "end": 3}},
            "rules": [{"kind": "prefix", "options": {"text": "id-"}}],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["payloads"] == ["id-1", "id-2", "id-3"]
    assert body["count"] == 3


async def test_the_api_starts_a_job_with_an_attack_type(client, origin_url):
    """A job is started with the attack type it was given."""
    created = await client.post(
        "/api/fuzz/jobs",
        json={
            "method": "GET",
            "url": f"{origin_url}/attack?a=§a§&b=§b§",
            "payloads": ["one", "two"],
            "attack_type": "battering-ram",
            "start": False,
        },
    )
    assert created.status_code == 200
    job = created.json()
    assert job["attack_type"] == "battering-ram"
    assert job["total"] == 2


async def test_the_api_carries_the_sets_the_rules_and_the_grep(client, origin_url):
    """Everything the run needs survives the trip through the interface."""
    created = await client.post(
        "/api/fuzz/jobs",
        json={
            "method": "GET",
            "url": f"{origin_url}/full?a=§a§&b=§b§",
            "attack_type": "cluster-bomb",
            "payload_sets": [["a1"], ["b1", "b2"]],
            "rules": [{"kind": "prefix", "options": {"text": "x-"}}],
            "grep_match": "needle",
            "grep_extract": r'"id":\s*(\d+)',
            "start": False,
        },
    )
    assert created.status_code == 200
    job = created.json()
    assert job["attack_type"] == "cluster-bomb"
    assert job["payload_sets"] == [["a1"], ["b1", "b2"]]
    assert job["rules"][0]["kind"] == "prefix"
    assert job["grep_match"] == "needle"
    assert job["grep_extract"] == r'"id":\s*(\d+)'
    assert job["total"] == 2


async def test_the_results_are_seen_while_the_job_is_still_running(app, origin_url, monkeypatch):
    """A running job shows the results that already came in."""
    request = Request(method="GET", url=f"{origin_url}/stream?q=§q§")
    job = app.fuzzer.create_job(request, ["one", "two", "three"], attack_type="sniper")

    delays = {"one": 0.01, "two": 0.2, "three": 0.4}
    original = app.fuzzer.client.send

    async def slow_send(req):
        payload = req.url.rsplit("=", 1)[-1]
        await asyncio.sleep(delays.get(payload, 0.01))
        return await original(req)

    monkeypatch.setattr(app.fuzzer.client, "send", slow_send)

    await app.fuzzer.start(job.id)
    try:
        await asyncio.sleep(0.12)
        assert len(job.results) == 1
        assert job.status == "running"
    finally:
        app.fuzzer.stop(job.id)


async def test_a_position_filter_leaves_the_other_positions_alone(app):
    """Only the positions that were asked for are worked on."""
    job = app.fuzzer.create_job(_request(), ["one"], attack_type="sniper", position_filter="b")
    combinations = job.combinations()
    assert len(combinations) == 1
    assert combinations[0][0][0].name == "b"


async def test_a_run_without_positions_does_nothing(app):
    """A template without markers has nothing to fuzz."""
    job = app.fuzzer.create_job(Request(method="GET", url="http://127.0.0.1/plain"), ["one"])
    assert job.total == 0
    assert job.combinations() == []


def test_a_position_without_payloads_stays_blank(app):
    """An empty list leaves its position empty in every request."""
    job = app.fuzzer.create_job(
        _request(),
        attack_type="cluster-bomb",
        payload_sets=[["a1"], []],
    )
    combinations = job.combinations()
    assert len(combinations) == 1
    _positions, payloads = combinations[0]
    assert payloads == ["a1", ""]


def test_the_sets_line_up_with_the_positions(app):
    """The first list belongs to the first position."""
    job = app.fuzzer.create_job(
        _request(),
        attack_type="pitchfork",
        payload_sets=[["a1"], ["b1"]],
    )
    combinations = job.combinations()
    assert [position.name for position in combinations[0][0]] == ["a", "b"]
    assert combinations[0][1] == ["a1", "b1"]


def test_one_list_is_used_for_every_position(app):
    """A single list is shared by all the positions."""
    job = app.fuzzer.create_job(
        _request(),
        attack_type="cluster-bomb",
        payload_sets=[["one", "two"]],
    )
    combinations = job.combinations()
    assert len(combinations) == 4
    assert sorted(payloads for _positions, payloads in combinations) == [
        ["one", "one"],
        ["one", "two"],
        ["two", "one"],
        ["two", "two"],
    ]
