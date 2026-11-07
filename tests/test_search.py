"""Search narrows the list. It must never show a document the user cannot open."""
import datetime

import pytest

from helpers import give, login, make_doc, post, query, text, unique, active_grant_id

SEARCH_STARTS_AT = "<!-- results -->"       # the results come after this marker


def results(response):
    return text(response).split(SEARCH_STARTS_AT)[-1]


def test_dave_cannot_find_a_contract_that_is_not_shared_with_him(dave):
    page = results(dave.get("/documents?title=contract"))
    assert "Acme" not in page and "No documents you can open" in page


def test_bobs_own_contract_is_found_by_bob(bob):
    assert "Customer contract - Acme" in results(bob.get("/documents?title=acme"))


def test_nobody_but_the_owner_finds_a_private_document(app, alice):
    title = unique("private")
    make_doc(alice, title=title)
    assert title in results(alice.get(f"/documents?title={title}"))
    for who in ("bob", "carol", "dave", "admin"):
        assert title not in results(login(app, who).get(f"/documents?title={title}"))


@pytest.mark.parametrize("evil", ["%", "_", "\\", "' OR 1=1 --", "a%' UNION SELECT 1--", "%25"])
def test_hostile_search_text_finds_nothing_and_breaks_nothing(bob, evil):
    response = bob.get("/documents", query_string={"title": evil})
    assert response.status_code == 200
    assert "Salary letter - Carol" not in results(response)        # alice's, not bob's
    assert "Customer contract" not in results(response)            # percent is not a wildcard


def test_search_text_is_escaped_on_the_page(carol):
    page = text(carol.get('/documents?title="><script>alert(1)</script>'))
    assert "<script>alert(1)" not in page


def test_category_filter(carol):
    assert "Site drawing rev B" in results(carol.get("/documents?category=Drawing"))
    assert "Site drawing rev B" not in results(carol.get("/documents?category=Contract"))
    unknown = results(carol.get("/documents?category=Nope"))        # ignored, shows everything
    assert "Site drawing rev B" in unknown


def test_owner_filter(carol):
    assert "Salary letter - Carol" in results(carol.get("/documents?owner=alice"))
    assert "No documents" in results(carol.get("/documents?owner=bob"))


def test_date_filters_include_the_whole_last_day(carol):
    today = query("SELECT (now() AT TIME ZONE 'utc')::date d")[0]["d"].isoformat()
    assert "Salary letter - Carol" in results(carol.get(f"/documents?date_from={today}&date_to={today}"))
    assert "No documents" in results(carol.get("/documents?date_to=2000-01-01"))
    assert "No documents" in results(carol.get("/documents?date_from=2999-01-01"))


def test_a_bad_date_is_ignored_with_a_message(carol):
    response = carol.get("/documents?date_from=garbage")
    assert response.status_code == 200 and "Dates must look like" in text(response)


def test_search_stops_showing_a_document_the_moment_access_is_revoked(alice, dave):
    title = unique("vanish")
    doc = make_doc(alice, title=title)
    give(alice, doc, "dave", "read")
    assert title in results(dave.get(f"/documents?title={title}"))
    post(alice, f"/documents/{doc}/grants/{active_grant_id(doc, 'dave')}/revoke")
    assert title not in results(dave.get(f"/documents?title={title}"))


def test_deleted_documents_are_not_searchable(alice):
    title = unique("gone")
    doc = make_doc(alice, title=title)
    post(alice, f"/documents/{doc}/delete")
    assert title not in results(alice.get(f"/documents?title={title}"))


def test_search_needs_a_login(anon):
    assert anon.get("/documents?title=x").status_code == 302