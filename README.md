# Vault — лабораторная работа №2

Простой GraphQL-сервис для управления пользователями и OAuth-клиентами.

## Технологии

- Python 3.11
- FastAPI
- Ariadne GraphQL
- SQLAlchemy 2.x
- Alembic
- SQLite
- Argon2id, zxcvbn
- JWT HS256
- HTML и JavaScript
- Pytest

## Установка

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Настройка

Скопировать `.env.example` в `.env` и заменить `JWT_SECRET` и `PASSWORD_PEPPER` на случайные секретные значения.

## База данных

Для нового проекта сначала выполнить `alembic init alembic` и настроить `alembic/env.py`.

Затем создать и применить миграцию:

```bash
alembic revision --autogenerate -m "Initial tables"
alembic upgrade head
```

При последующих запусках достаточно `alembic upgrade head`.

## Запуск

```bash
python run.py
```

Адреса:

- `http://127.0.0.1:8000/docs` — REST API
- `http://127.0.0.1:8000/graphql` — GraphQL
- `http://127.0.0.1:8000/admin/` — админка

## Пример GraphQL

```graphql
{
  me {
    email
    isAdmin
  }
}
```

Пример ответа:

```json
{
  "data": {
    "me": {
      "email": "admin@example.com",
      "isAdmin": true
    }
  }
}
```

Для выполнения защищённых запросов требуется JWT-токен в заголовке Authorization.

## Тестирование

```bash
python -m pytest -v
```

Тесты используют отдельную базу SQLite.

## Структура

- `app/db` — подключение к базе данных
- `app/models` — модели SQLAlchemy
- `app/core` — пароли, JWT, авторизация
- `app/auth` — регистрация и вход
- `app/graphql` — GraphQL API
- `app/audit` — аудит действий
- `app/static` — админ-панель
- `alembic` — миграции базы данных
- `tests` — автоматические тесты

Файлы `.env` и `*.db` не публикуются в GitHub.