import atexit
from typing import Union

from flask import Flask, jsonify, request
from flask.views import MethodView
from sqlalchemy import Column, Integer, String, DateTime, create_engine, func, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import IntegrityError
import pydantic
from flask_bcrypt import Bcrypt

PG_DSN = 'postgresql://postgres:postgres@127.0.0.1:5432/netology_ads'

engine = create_engine(PG_DSN)
Base = declarative_base()
Session = sessionmaker(bind=engine)

atexit.register(lambda: engine.dispose())

app = Flask('app')
bcrypt = Bcrypt(app)


def hash_password(password: str):
    password = password.encode()
    hashed = bcrypt.generate_password_hash(password)
    return hashed.decode()


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)
    ads = relationship('AdModel', backref='user')


class AdModel(Base):
    __tablename__ = "ads"
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    description = Column(String)
    created_on = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey('users.id'))


Base.metadata.create_all(engine)


class CreateUserSchema(pydantic.BaseModel):
    email: str
    password: str


class CreateAdSchema(pydantic.BaseModel):
    title: str
    description: str
    user_id: int


def validate(data: dict, schema_class):
    try:
        return schema_class(**data).dict()
    except pydantic.ValidationError as er:
        raise APIException(400, er.errors())


class APIException(Exception):
    def __init__(self, status_code: int, message: Union[str, list, dict]):
        self.status_code = status_code
        self.message = message


@app.errorhandler(APIException)
def error_handler(error: APIException):
    response = jsonify({
        'status': 'error',
        'message': error.message})
    response.status_code = error.status_code
    return response


class UserView(MethodView):

    def get(self, user_id: int):
        with Session() as session:
            user = session.query(UserModel).get(user_id)
            if user is None:
                raise APIException(404, 'user not found')

            return jsonify({
                'id': user.id,
                'email': user.email
            })

    def post(self):
        user_data = validate(request.json, CreateUserSchema)
        user_data['password'] = hash_password(user_data['password'])
        with Session() as session:
            new_user = UserModel(**user_data)
            session.add(new_user)
            try:
                session.commit()
            except IntegrityError:
                raise APIException(400, 'email is busy')

            return jsonify({
                'id': new_user.id,
                'email': new_user.email
            })

    def patch(self, user_id: int):
        user_data = request.json
        if 'password' in user_data:
            user_data['password'] = hash_password(user_data['password'])
        with Session() as session:
            user = session.query(UserModel).get(user_id)
            for field, value in user_data.items():
                setattr(user, field, value)
            session.add(user)
            try:
                session.commit()
            except IntegrityError:
                raise APIException(400, 'email is busy')

            return jsonify({
                'id': user.id,
                'email': user.email
            })

    def delete(self, user_id: int):
        with Session() as session:
            user = session.query(UserModel).get(user_id)
            session.delete(user)
            session.commit()
            return jsonify({'status': 'deleted'})


class AdView(MethodView):

    def get(self, ad_id: int):
        with Session() as session:
            ad = session.query(AdModel).get(ad_id)
            if ad is None:
                raise APIException(404, 'ad not found')

            return jsonify({
                'id': ad.id,
                'title': ad.title,
                'description': ad.description,
                'user_id': ad.user_id
            })

    def post(self):
        ad_data = validate(request.json, CreateAdSchema)
        with Session() as session:
            new_ad = AdModel(**ad_data)
            session.add(new_ad)
            session.commit()

            return jsonify({
                'id': new_ad.id,
                'title': new_ad.title,
                'description': new_ad.description,
                'user_id': new_ad.user_id
            })

    def patch(self, ad_id: int):
        ad_data = request.json
        with Session() as session:
            ad = session.query(AdModel).get(ad_id)
            for field, value in ad_data.items():
                setattr(ad, field, value)
            session.add(ad)
            session.commit()

            return jsonify({
                'id': ad.id,
                'title': ad.title,
                'description': ad.description,
                'user_id': ad.user_id
            })

    def delete(self, ad_id: int):
        with Session() as session:
            ad = session.query(AdModel).get(ad_id)
            session.delete(ad)
            session.commit()
            return jsonify({'status': 'deleted'})


app.add_url_rule('/users/<int:user_id>', view_func=UserView.as_view('users'), methods=['GET', 'PATCH', 'DELETE'])
app.add_url_rule('/users/', view_func=UserView.as_view('users_create'), methods=['POST'])

app.add_url_rule('/ads/<int:ad_id>', view_func=AdView.as_view('ads'), methods=['GET', 'PATCH', 'DELETE'])
app.add_url_rule('/ads/', view_func=AdView.as_view('ads_create'), methods=['POST'])

if __name__ == '__main__':
    app.run()
