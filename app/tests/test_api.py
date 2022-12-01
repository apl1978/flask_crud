import requests

from app.tests.config import API_URL


def test_root():
    response = requests.get(API_URL)
    assert response.status_code == 404


# -------------------- Users Testing ---------------------------------

def test_get_user_by_id(create_user):
    response = requests.get(f'{API_URL}/users/{create_user["id"]}')
    assert response.status_code == 200
    response_data = response.json()
    assert response_data['email'] == create_user['email']


def test_get_user_not_exists():
    response = requests.get(f'{API_URL}/users/999999')
    assert response.status_code == 404


def test_create_user():
    response = requests.post(f'{API_URL}/users/', json={'email': 'new_user@email.ru', 'password': '2222'})
    assert response.status_code == 200
    response_data = response.json()
    assert 'id' in response_data
    assert response_data['email'] == 'new_user@email.ru'


def test_create_user_same_email():
    response = requests.post(f'{API_URL}/users/', json={'email': 'new_user2@email.ru', 'password': '3333'})
    response = requests.post(f'{API_URL}/users/', json={'email': 'new_user2@email.ru', 'password': '4444'})
    assert response.status_code == 400
    response_data = response.json()
    assert response_data['message'] == 'email is busy'


def test_create_user_without_email():
    response = requests.post(f'{API_URL}/users/', json={'password': '5555'})
    assert response.status_code == 400
    assert response.json() == {'message': [{'loc': ['email'], 'msg': 'field required', 'type': 'value_error.missing'}],
                               'status': 'error'}


def test_patch_user(create_user):
    response = requests.patch(f'{API_URL}/users/{create_user["id"]}', json={'email': 'patch_user@email.ru'})
    assert response.status_code == 200
    response_data = response.json()
    assert response_data['email'] == 'patch_user@email.ru'


def test_delete_user(create_user):
    response = requests.delete(f'{API_URL}/users/{create_user["id"]}')
    assert response.status_code == 200
    response_data = response.json()
    assert response_data['status'] == 'deleted'


# -------------------- Ads Testing ---------------------------------

def test_get_ad_by_id(create_ad):
    response = requests.get(f'{API_URL}/ads/{create_ad["id"]}')
    assert response.status_code == 200
    response_data = response.json()
    assert response_data['title'] == create_ad['title']


def test_get_ad_not_exists():
    response = requests.get(f'{API_URL}/ads/999999')
    assert response.status_code == 404


def test_create_ad(create_user):
    response = requests.post(f'{API_URL}/ads/', json={'title': 'new_title', 'description': 'new_description',
                                                      'user_id': create_user["id"]})
    assert response.status_code == 200
    response_data = response.json()
    assert 'id' in response_data
    assert response_data['title'] == 'new_title'
    assert response_data['user_id'] == create_user["id"]


def test_patch_ad(create_ad):
    response = requests.patch(f'{API_URL}/ads/{create_ad["id"]}', json={'title': 'patch_title'})
    assert response.status_code == 200
    response_data = response.json()
    assert response_data['title'] == 'patch_title'


def test_delete_ad(create_ad):
    response = requests.delete(f'{API_URL}/ads/{create_ad["id"]}')
    assert response.status_code == 200
    response_data = response.json()
    assert response_data['status'] == 'deleted'
