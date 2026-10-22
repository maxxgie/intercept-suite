"""Tests for the comparer: the differences, the similarities and the view."""

from __future__ import annotations

import json

from intercept.tools.comparer import (
    COMPARISON_KINDS,
    Comparer,
    compare_bytes,
    compare_documents,
    diff_lines,
    extract_tokens,
    guess_kind,
)

# ------------------------------------------------------------------- the diff


def test_two_texts_that_are_the_same_have_no_differences():
    comparison = compare_documents("hello world", "hello world")
    assert comparison.identical is True
    assert comparison.differences == []
    assert comparison.summary == "The two are the same."


def test_a_difference_is_found():
    comparison = compare_documents("hello world", "hello there")
    assert comparison.identical is False
    assert comparison.differences or comparison.rows
    assert "difference" in comparison.summary


def test_the_lines_are_put_next_to_each_other():
    rows = diff_lines("one\ntwo\nthree", "one\ntwo changed\nthree")
    assert [row.kind for row in rows] == ["same", "different", "same"]
    assert rows[1].left == "two"
    assert rows[1].right == "two changed"


def test_a_line_that_is_only_on_one_side_is_marked():
    rows = diff_lines("one\ntwo", "one")
    assert any(row.kind == "removed" for row in rows)


def test_the_changed_part_of_a_line_is_marked():
    rows = diff_lines("status: 200 OK", "status: 404 Not Found")
    changed = [row for row in rows if row.kind == "different"]
    assert changed
    left_span = changed[0].left_span
    assert left_span is not None
    assert "200" in changed[0].left[left_span[0] : left_span[1]]


# --------------------------------------------------------------------- json


def test_json_keys_that_changed_are_found():
    comparison = compare_documents(
        json.dumps({"user": {"name": "ann", "role": "admin"}}),
        json.dumps({"user": {"name": "ann", "role": "guest"}}),
        "json",
    )
    paths = {difference.path for difference in comparison.differences}
    assert "user.role" in paths


def test_json_keys_that_are_only_on_one_side_are_found():
    comparison = compare_documents('{"a": 1}', '{"a": 1, "b": 2}', "json")
    notes = {difference.path: difference.note for difference in comparison.differences}
    assert notes.get("b") == "only in B"


def test_json_values_that_are_the_same_are_similarities():
    comparison = compare_documents('{"a": 1, "b": 2}', '{"a": 1, "b": 3}', "json")
    same = {similarity.path for similarity in comparison.similarities}
    assert "a" in same


def test_json_lists_are_compared_item_by_item():
    comparison = compare_documents('{"a": [1, 2]}', '{"a": [1, 3]}', "json")
    paths = {difference.path for difference in comparison.differences}
    assert "a[1]" in paths


def test_json_that_cannot_be_read_says_so():
    comparison = compare_documents("not json", "also not json", "json")
    assert comparison.differences


# ---------------------------------------------------------------------- xml


def test_xml_attributes_that_changed_are_found():
    comparison = compare_documents(
        "<root><a x='1'>text</a></root>", "<root><a x='2'>text</a></root>", "xml"
    )
    paths = {difference.path for difference in comparison.differences}
    assert "root/a@x" in paths


def test_xml_elements_that_are_only_on_one_side_are_found():
    comparison = compare_documents("<root><a/></root>", "<root><b/></root>", "xml")
    notes = {difference.note for difference in comparison.differences}
    assert "only in A" in notes
    assert "only in B" in notes


def test_xml_text_that_is_the_same_is_a_similarity():
    comparison = compare_documents("<root><a>same</a></root>", "<root><a>same</a></root>", "xml")
    assert comparison.similarities


def test_xml_that_cannot_be_read_says_so():
    comparison = compare_documents("<root>", "<root>", "xml")
    assert comparison.identical is True


# --------------------------------------------------------------------- html


def test_html_text_that_changed_is_found():
    comparison = compare_documents(
        "<html><body><h1>Hi</h1></body></html>",
        "<html><body><h1>Hello</h1></body></html>",
        "html",
    )
    assert any(difference.left == "Hi" for difference in comparison.differences)


def test_html_that_is_the_same_has_no_differences():
    page = "<html><body><h1>Hi</h1></body></html>"
    comparison = compare_documents(page, page, "html")
    assert comparison.differences == []
    assert comparison.similarities


# -------------------------------------------------------------------- binary


def test_the_bytes_that_differ_are_found():
    comparison = compare_bytes(b"hello world", b"hello w0rld", "binary")
    assert len(comparison.differences) == 1
    assert comparison.differences[0].path == "offset 7"
    assert comparison.differences[0].left == "6f"
    assert comparison.differences[0].right == "30"


def test_a_file_that_is_longer_says_so():
    comparison = compare_bytes(b"abc", b"abcde", "binary")
    notes = {difference.note for difference in comparison.differences}
    assert "only in B" in notes


def test_two_files_that_are_the_same_are_similar():
    comparison = compare_bytes(b"abc", b"abc", "binary")
    assert comparison.identical is True
    assert comparison.similarities


# -------------------------------------------------------------------- tokens


def test_tokens_are_found():
    tokens = extract_tokens("csrftoken=abcdef123456&session=zzzzzz111111")
    values = {token.value for token in tokens}
    assert "abcdef123456" in values


def test_a_json_web_token_is_found():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"
    assert any(item.value == token for item in extract_tokens(f"data={token}"))


def test_the_tokens_that_are_the_same_are_similarities():
    comparison = compare_documents(
        "csrftoken=abcdef123456&session=zzzzzz111111",
        "csrftoken=abcdef123456&session=yyyyyy222222",
        "tokens",
    )
    values = {similarity.value for similarity in comparison.similarities}
    assert "abcdef123456" in values
    paths = {difference.path for difference in comparison.differences}
    assert "session" in paths


# ------------------------------------------------------------------ messages


def test_a_request_is_compared_by_its_parts():
    left = "POST /login HTTP/1.1\r\nHost: a.com\r\nX-Token: one\r\n\r\nbody"
    right = "POST /login HTTP/1.1\r\nHost: a.com\r\nX-Token: two\r\n\r\nbody"
    comparison = compare_documents(left, right, "request")
    paths = {difference.path for difference in comparison.differences}
    assert "x-token" in paths
    same = {similarity.path for similarity in comparison.similarities}
    assert "host" in same


def test_the_start_line_is_compared():
    left = "GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n"
    right = "GET /b HTTP/1.1\r\nHost: a.com\r\n\r\n"
    comparison = compare_documents(left, right, "request")
    paths = {difference.path for difference in comparison.differences}
    assert "the first line" in paths


def test_a_response_is_compared_by_its_status():
    left = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello"
    right = "HTTP/1.1 500 Error\r\nContent-Type: text/html\r\n\r\nhello"
    comparison = compare_documents(left, right, "response")
    paths = {difference.path for difference in comparison.differences}
    assert "the first line" in paths


def test_the_body_of_a_request_is_compared_as_json():
    left = 'POST /a HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"x": 1}'
    right = 'POST /a HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"x": 2}'
    comparison = compare_documents(left, right, "request")
    assert any(difference.kind.startswith("body.") for difference in comparison.differences)


# ------------------------------------------------------------------- guessing


def test_json_is_guessed():
    assert guess_kind(b'{"a": 1}', b'{"a": 2}') == "json"


def test_html_is_guessed():
    assert guess_kind(b"<html><body></body></html>", b"<html></html>") == "html"


def test_xml_is_guessed():
    assert guess_kind(b'<?xml version="1.0"?><a/>', b'<?xml version="1.0"?><b/>') == "xml"


def test_text_is_guessed():
    assert guess_kind(b"hello", b"there") == "text"


def test_the_kinds_are_the_ones_that_are_advertised():
    for kind in ("json", "xml", "html", "tokens", "binary", "request", "response"):
        assert kind in COMPARISON_KINDS


# ------------------------------------------------------------------- the api


async def test_the_api_compares_two_values(client):
    response = await client.post(
        "/api/comparer/compare",
        json={"left": "one\ntwo", "right": "one\nthree", "kind": "text"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["identical"] is False
    assert data["rows"]


async def test_the_api_compares_two_exchanges(client, app, origin_url, proxy_url):
    import httpx

    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as browser:
        await browser.get(f"{origin_url}/one")
        await browser.get(f"{origin_url}/two")
    await app.store.flush()

    items = (await client.get("/api/traffic")).json()["items"]
    assert len(items) == 2
    response = await client.post(
        "/api/comparer/exchanges",
        json={"left_id": items[0]["id"], "right_id": items[1]["id"], "part": "request"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["rows"]
    paths = {difference["path"] for difference in data["differences"]}
    assert "the first line" in paths


async def test_the_api_reports_an_exchange_that_is_not_there(client):
    response = await client.post(
        "/api/comparer/exchanges",
        json={"left_id": "nope", "right_id": "nope", "part": "response"},
    )
    assert response.status_code == 404


async def test_the_api_compares_json(client):
    response = await client.post(
        "/api/comparer/compare",
        json={"left": '{"a": 1}', "right": '{"a": 2}', "kind": "json"},
    )
    assert response.status_code == 200
    paths = {difference["path"] for difference in response.json()["differences"]}
    assert "a" in paths


async def test_the_api_compares_base64(client):
    import base64 as encoder

    left = encoder.b64encode(b"hello").decode()
    right = encoder.b64encode(b"hallo").decode()
    response = await client.post(
        "/api/comparer/compare",
        json={"left": left, "right": right, "kind": "binary", "base64": True},
    )
    assert response.status_code == 200
    assert response.json()["differences"]


async def test_the_api_lists_the_kinds(client):
    response = await client.get("/api/comparer/kinds")
    assert response.status_code == 200
    assert "json" in response.json()["kinds"]


def test_the_comparer_object_answers():
    result = Comparer().compare("one", "two", "text")
    assert result["kind"] == "text"
    assert result["rows"]


def test_the_catalogue_lists_the_kinds():
    assert "json" in Comparer().catalog()["kinds"]
