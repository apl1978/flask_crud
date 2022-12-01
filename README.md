# Домашнее задание к лекции «Flask»

##Установка и запуск

Установить библиотеки из файла requirements.txt командой

pip install -r requirements.txt

В файле app.py прописать параметры подключения к базе данных в константе PG_DSN.

Запустить app.py.

По умолчанию, приложение запускается по адресу и порту 'http://127.0.0.1:5000'.
При необходимости поправить адрес и порт в файле tests/config.py в константе API_URL.

Запустить тесты

pytest tests -v -s

## Задание 1

Вам нужно написать REST API (backend) для сайта объявлений.

Должны быть реализованы методы создания/удаления/редактирования объявления.    

У объявления должны быть следующие поля: 
- заголовок
- описание
- дата создания
- владелец

Результатом работы является API, написанное на Flask.

Этапы выполнения задания:

1. Сделайте роут на Flask.
2. POST метод должен создавать объявление, GET - получать объявление, DELETE - удалять объявление.

## Задание 2 *(не обязательное)

Добавить систему прав.

Создавать объявление может только авторизованный пользователь.
Удалять/редактировать может только владелец объявления.
В таблице с пользователями должны быть как минимум следующие поля: идентификатор, почта и хэш пароля.