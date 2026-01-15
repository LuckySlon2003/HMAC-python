# HMAC Python Service

Учебный HTTP‑сервис для подписи и проверки сообщений с помощью **HMAC‑SHA256**.

Проект демонстрирует:
- работу с HMAC;
- валидацию входных данных;
- конфигурацию через `config.json`;
- тестирование FastAPI;
- базовую ротацию секрета.

## Требования к окружению и установка:
Для работы потребуется менеджер зависмостей `uv`. Установить его по инструкции из GitHub репозитория astral-sh/uv:
https://github.com/astral-sh/uv?tab=readme-ov-file#installation

Установка зависимостей происходит через Make команду:
```bash
make sync
```

## Запуск тестов
Для запуска тестов можно воспользоваться Make командой:
```bash
make test
```

## Запуск сервера
Поднять сервер с API можно через команду Make:
```bash
make run/api
```

# Формат `config.json`

```json
{
  "hmac_alg": "SHA256",
  "secret": "9f3c2e6a7b1d4a8c5e9b0f2d6c4a7e8b1f5d3a9c0e2b4d6f8a7c5b9e1d2a",
  "log_level": "info",
  "listen": "0.0.0.0:8080",
  "max_msg_size_bytes": 1048576
}
```

### Описание полей
- **hmac_alg** — алгоритм HMAC
- **secret** — hex‑кодированный секрет
- **log_level** — уровень логирования
- **listen** — адрес и порт сервера
- **max_msg_size_bytes** — максимальный размер сообщения

Рекомендуется установить права:
```bash
chmod 600 config.json
```

## Запуск сервера

### Локально
```bash
uv run python -m src.app
```

## Примеры `curl`

### Подпись сообщения

```bash
curl -X POST http://127.0.0.1:8080/sign   -H "Content-Type: application/json"   -d '{"msg": "hello"}'
```

Ответ:
```json
{ 
  "msg": "string", 
  "signature": "base64url" 
}
```

### Проверка подписи

```bash
curl -X POST http://127.0.0.1:8080/verify   -H "Content-Type: application/json"   -d '{
    "msg": "hello",
    "signature": "X5Y8c1EwZQJ9xXxK..."
  }'
```

Ответ:
```json
{"ok": true}
```

## Ротация секрета

Консольная утилита:

```bash
uv run rotate-secret --print
```

- генерирует новый hex‑секрет;
- обновляет `config.json`;
- выводит новый секрет в stdout (опционально).

## Ограничения учебной реализации

- HMAC — это **симметричная** криптография  
  (не асимметричная электронная подпись).
- Ротация секрета:
  - простая (замена одного секрета);
  - без периода совместимости старых подписей.
