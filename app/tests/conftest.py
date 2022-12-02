import time
from app.app import engine, Base, Session, UserModel, AdModel, hash_password
from pytest import fixture


@fixture(scope="session", autouse=True)
def prepare_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


@fixture()
def create_user():
    with Session() as session:
        new_user = UserModel(email=f'user{time.time()}@email.ru', password=hash_password(password='1111'))
        session.add(new_user)
        session.commit()
        return {
            'id': new_user.id,
            'email': new_user.email
        }


@fixture()
def create_ad():
    with Session() as session:
        new_user = UserModel(email=f'user_{time.time()}@email.ru', password=hash_password(password='1234'))
        session.add(new_user)
        session.commit()
        new_ad = AdModel(title='test', description='test_descr', user_id=new_user.id)
        session.add(new_ad)
        session.commit()

        return {
            'id': new_ad.id,
            'title': new_ad.title,
            'description': new_ad.description,
            'user_id': new_ad.user_id,
            'user_email': new_user.email
        }
