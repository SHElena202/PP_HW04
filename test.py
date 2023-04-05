import pytest
from docker.context import context

from api import *


class MockStore:
    def cache_get(*args, **kwargs):
        return None

    def cache_set(*args, **kwargs):
        pass

    def get(*args,**kwargs):
        return []

class MockStoreError:
    def get(*args, **kwargs):
        raise ConnectionRefusedError


@pytest.fixture()
def mock_store(monkeypatch):
    def mock_set():
        return MockStore

    monkeypatch.setattr(store, 'Store', mock_set)


@pytest.fixture()
def mock_store_error(monkeypatch):
    def mock_set():
        return MockStoreError

    monkeypatch.setattr(store, 'Store', mock_set)


def get_response(mock_store, request, context):
    response = method_handler(
        request=dict(body=request, headers={}),
        ctx=context,
        store=store.Store,
    )
    return response


def valid_auth_for_admin():
    return hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()


def test_empty_request(mock_store):
    _, code = get_response(mock_store, {})
    assert INVALID_REQUEST == code


@pytest.mark.parametrize(
    'request_json',
    [
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}},
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arguments": {}},
        {"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arguments": {}},
    ]
)
def test_bad_auth(mock_store, request_json):
    _, code = get_response(mock_store, request_json)
    assert FORBIDDEN == code


@pytest.mark.parametrize(
    'request_response',
    [
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score"},
        {"account": "horns&hoofs", "login": "h&f", "arguments": {}},
        {"account": "horns&hoofs", "method": "online_score", "arguments": {}},
    ]
)
def test_invalid_method_request(mock_store, request_response):
    request_json, response_valid = request_response
    response, code = get_response(mock_store, request_json)
    assert INVALID_REQUEST == code
    assert response_valid == response


@pytest.mark.parametrize(
    'arguments_response',
    [
        {},
        {"phone": "79175002040"},
        {"phone": "89175002040", "email": "stupnikov@otus.ru"},
        {"phone": "79175002040", "email": "stupnikovotus.ru"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.1890"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000", "first_name": 1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
         "first_name": "s", "last_name": 2},
        {"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"},
        {"email": "stupnikov@otus.ru", "gender": 1, "last_name": 2},
    ]
)
def test_invalid_score_request(mock_store, arguments_response, response_valid=None):
    arguments_response, response_valid == arguments_response
    request_json = {"account": "test", "login": "h&f", "method": "online_score", "arguments": arguments_response}
    response, code = get_response(mock_store, request_json)
    assert INVALID_REQUEST == code
    assert response_valid == response


@pytest.mark.parametrize([
    {"phone": "79175002040", "email": "stupnikov@otus.ru"},
    {"phone": 79175002040, "email": "stupnikov@otus.ru"},
    {"gender": 1, "birthday": "01.01.2000", "first_name": "a", "last_name": "b"},
    {"gender": 0, "birthday": "01.01.2000"},
    {"gender": 2, "birthday": "01.01.2000"},
    {"first_name": "a", "last_name": "b"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
     "first_name": "a", "last_name": "b"},
])
def test_ok_score_request(mock_store, arguments):
    request_json = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
    response, code = get_response(request_json)
    assert OK == code, arguments
    score = response.get("score")
    assert isinstance(score, (int, float)) and score >= 0, arguments
    assert sorted(context["has"]), sorted(arguments.keys())


def test_ok_score_admin_request(mock_store):
    arguments = {"phone": "79175002040", "email": "stupnikov@otus.ru"}
    request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": arguments}
    response, code = get_response(request)
    assert OK == code
    score = response.get("score")
    assert score == 42


@pytest.mark.parametrize([
    {},
    {"date": "20.07.2017"},
    {"client_ids": [], "date": "20.07.2017"},
    {"client_ids": {1: 2}, "date": "20.07.2017"},
    {"client_ids": ["1", "2"], "date": "20.07.2017"},
    {"client_ids": [1, 2], "date": "XXX"},
])
def test_invalid_interests_request(mock_store, arguments):
    request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": arguments}
    response, code = get_response(request)
    assert INVALID_REQUEST == code, arguments
    assert len(response)


@pytest.mark.parametrize([
    {"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")},
    {"client_ids": [1, 2], "date": "19.07.2017"},
    {"client_ids": [0]},
])
def test_ok_interests_request(mock_store, arguments):
    request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": arguments}
    response, code = get_response(request)
    assert OK == code, arguments
    assert len(arguments["client_ids"]), len(response)
    assert all(v and isinstance(v, list) and all(isinstance(i, (bytes, str)) for i in v) for v in response.values())
    assert context.get("nclients"), len(arguments["client_ids"])

