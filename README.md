# DataQR-API

<p align="center">
   <img src="https://img.shields.io/badge/C%2B%2B-14-blue" alt="C++ Version">
   <img src="https://img.shields.io/badge/Restbed-4.8-green" alt="Restbed Version">
   <img src="https://img.shields.io/badge/nlohmann%2Fjson-3.11.2-blueviolet" alt="nlohmann/json Version">
   <img src="https://img.shields.io/badge/Crypto%2B%2B-8.7-yellowgreen" alt="Crypto++ Version">
   <img src="https://img.shields.io/badge/MySQL-8.0%2F5.7-lightgrey" alt="MySQL Version">
</p>
<p align="center">
   <img src="https://img.shields.io/badge/qrencode-4.1.1-important" alt="libqrencode Version">
   <img src="https://img.shields.io/badge/libpng-1.6.39-informational" alt="libpng Version">
   <img src="https://img.shields.io/badge/version-1.0-yellow" alt="Application Version">
   <img src="https://img.shields.io/badge/license-MIT-red" alt="License">
</p>

## REST API server that creates QR codes.

### About

The server part of the service and API.
It works in multithreaded mode.
The application registers and authorizes users.
The application turns to the MySQL server and provides information about organizations and projects.
It encodes the information and outputs it as a QR code.

### Documentation

The directory `source/` must be created in the root directory.
It should contain a file `sql_settings.txt`.
Each line of the file contains one element for connecting to the MySQL server.

File structure:
- ip DB
- username
- password
- port DB

Fix the file `ServerSettings.h` to change names of endpoints and the number of threads used.
By default, 4 threads are used.
Fix the file or use `std::thread::hardware_concurrency()`.

MySQL server uses two databases.
The first one is for storing user data.
And the second for storing organizations' data.
See the addendum.

### Developers

- [Valendovsky](https://github.com/valendovsky)

### License

Project DataQR-API is distributed under the MIT license.

---

## REST API сервер, создающий QR коды.

### О проекте

Серверная часть сервиса и API, работает в многопоточном режиме.
Сервер отвечает за регистрацию и авторизацию пользователей.
Через обращение к MySQL серверу выдаёт необходимую информацию по организациям и проектам.
Производит кодирование информации и выдачу её в виде QR-кода.

### Документация

В корневой директории необходимо создать каталог `source/`.
Он должен содержать файл `sql_settings.txt`, где на каждой строке будет указано по одному элементу для подключения к MySQL серверу.

Структура файла:
- ip адрес БД
- имя пользователя
- пароль
- порт БД

Названия эндпоинтов и количество используемых потоков можно изменить в файле `ServerSettings.h`.
По умолчанию используется 4 потока, исправьте, или используйте метод `std::thread::hardware_concurrency()`.

MySQL сервер использует две БД: одну для хранения данных пользователей, а вторую для хранения данных организаций.
См. дополнение.

### Разработчики

- [Valendovsky](https://github.com/valendovsky)

### Лицензия

Проект DataQR-API распространяется под лицензией MIT.

---

### Addendum / Дополнение

Таблица с данными пользователей / The table with user data:
| Field    | Type        | Null | Key | Default           | Extra          |
|----------|-------------|------|-----|-------------------|----------------|
| id       | int(11)     | NO   | PRI | NULL              | auto_increment |
| email    | varchar(30) | NO   | UNI | NULL              |                |
| password | varchar(32) | NO   |     | NULL              |                |
| name     | varchar(30) | NO   |     | NULL              |                |
| access   | int(11)     | NO   |     | 3                 |                |
| reg_date | datetime    | YES  |     | CURRENT_TIMESTAMP |                |

Таблица Refresh-токенов / Refresh-tokens table:
| Field         | Type        | Null | Key | Default           | Extra          |
|---------------|-------------|------|-----|-------------------|----------------|
| auth_id       | int(11)     | NO   | PRI | NULL              | auto_increment |
| email         | varchar(30) | YES  | UNI | NULL              |                |
| refresh       | varchar(69) | YES  |     | NULL              |                |
| auth_reg_date | datetime    | YES  |     | CURRENT_TIMESTAMP |                |

Таблица со списком организаций / The table with a list of organizations:
| Field    | Type        | Null | Key | Default | Extra          |
|----------|-------------|------|-----|---------|----------------|
| org_id   | int(11)     | NO   | PRI | NULL    | auto_increment |
| org_name | varchar(30) | YES  | UNI | NULL    |                |
