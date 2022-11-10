#ifndef SQLSETTINGS_H
#define SQLSETTINGS_H

#include <string>


// Содержит настройки подключения к БД MySQL
struct MySQLSettings
{
	std::string ipDB;
	std::string login;
	std::string password;
	int port;
	std::string usersDB;
	std::string orgDB;
};


// Константы для работы с MySQL
namespace SqlSettings
{
	const std::string USERS_DB    = "user_bd";        // тестовая БД для проверки подключения
	const std::string USERS_TABLE = "users";          // таблица с зарегистрированными пользователями
	const std::string AUTH_TABLE  = "auth";           // таблица с refresh-токенами
	const std::string ORG_DB      = "org_db";         // тестовая БД для хранения информации по организациям
	const std::string ORG_TABLE   = "organizations";  // таблица с зарегистрированными организациями

}

#endif // !SQLSETTINGS_H
