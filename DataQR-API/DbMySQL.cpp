#include "DbMySQL.h"

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <exception>
#include <mutex>

#include "SqlSettings.h"
#include "Structs.h"
#include "IWriteLog.h"
#include "ScreenLog.h"


extern std::mutex g_mtxSqlReg;
extern std::mutex g_mtxSqlAuth;


// Метод логирования информации
void DbMySQL::printInfo(const std::string& message, IWriteLog& typeLog)
{
	typeLog.writeLog("INFO DbMySQL " + message);
}

// Метод логирует ошибки MySQL и дополнительную информацию
void DbMySQL::errorMySQL(IWriteLog& typeLog, const std::string& message = "")
{
	if (message != "")
	{
		printInfo(message, typeLog);
	}

	printInfo("STANDART ERROR MySQL: " + std::string(mysql_error(&m_mysql)), typeLog);
}



// Инициализирует дескриптор
bool DbMySQL::initialization()
{
	ScreenLog toScreen;

	if (mysql_init(&m_mysql))
	{
		m_initialization = true;
		printInfo("initialization: The initialization is successful.", toScreen);

		return true;
	}
	else
	{
		errorMySQL(toScreen, "initialization: Can't create MySQL-descriptor");
		m_initialization = false;

		return false;
	}
}

// Устанавливает соединение с БД
bool DbMySQL::connect(const std::string& nameDB)
{
	ScreenLog toScreen;

	if (mysql_real_connect(&m_mysql, 
		                   m_settings.ipDB.c_str(), 
		                   m_settings.login.c_str(), 
		                   m_settings.password.c_str(), 
		                   nameDB.c_str(), 
		                   m_settings.port, 
		                   NULL, 0))
	{
		m_connection = true;
		printInfo("connect: The connect is successful.", toScreen);

		return true;
	}
	else
	{
		errorMySQL(toScreen, "connect: Can't connect to MySQL.");
		m_connection = false;

		return false;
	}
}

// Проверяет инициализацию и подключение
bool DbMySQL::checkConnect()
{
	ScreenLog toScreen;

	if ((!m_initialization) || (!m_connection))
	{
		printInfo("checkConnect: The initialization and the connection failed.", toScreen);

		return false;
	}
	else
	{
		printInfo("checkConnect: Successful connection.", toScreen);

		return true;
	}
}



// Меняет активную БД
bool DbMySQL::selectDB(const std::string& nameDB)
{
	// Проверка подключения к MySQL
	if (!checkConnect())
	{
		return false;
	}

	ScreenLog toScreen;

	// При успехе переключения БД возвращает 0
	if (mysql_select_db(&m_mysql, nameDB.c_str()))
	{
		errorMySQL(toScreen, "selectDB: Can't select DB.");

		return false;
	}
	else
	{
		printInfo("selectDB: The database is successfully replaced.", toScreen);
		return true;
	}
}

// Проверяет зарегистрирован ли пользователь в системе
int DbMySQL::checkReg(const std::string& userEmail)
{
	// Выбираем БД с данными пользователей
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// Проверяем зарегистрирован ли пользователь
	std::string checkCommand = "SELECT * FROM " + SqlSettings::USERS_TABLE + " WHERE email='" + userEmail + "';";
	if (mysql_query(&m_mysql, checkCommand.c_str()))
	{
		errorMySQL(toScreen, "checkReg: Invalid query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Результат запроса
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "checkReg: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		// email зарегистрирован
		printInfo("checkReg: The user with the email " + userEmail + " is registered.", toScreen);

		// Освобождаем память, использованную для результирующего набора
		mysql_free_result(res);

		return DbMySQL::CONFLICT;
	}
	else if (!mysql_eof(res))
	{
		// Если была ошибка чтения из результирующего набора
		errorMySQL(toScreen, "checkReg: Invalid fetch row.");

		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Пользователь не зарегистрирован
	printInfo("checkReg: The user with the email " + userEmail + " isn't registered.", toScreen);
	
	// Освобождаем память, использованную для результирующего набора
	mysql_free_result(res);

	return DbMySQL::NOT_ACCEPTABLE;
}



// Регистрирует пользователя в БД, проверяя не зарегистрировался ли пользователь ранее
int DbMySQL::registration(const UserData& user)
{
	std::lock_guard<std::mutex> lock(g_mtxSqlReg);

	// Выбираем БД с данными пользователей
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// Проверяем зарегистрирован ли пользователь
	int resultCheckReg = DbMySQL::checkReg(user.email);
	if (resultCheckReg != DbMySQL::NOT_ACCEPTABLE)
	{
		// Пользователь зарегистрирован или что-то пошло не так

		return resultCheckReg;
	}

	// Пользователь не зарегистрирован, добавляем его в БД
	std::string insertCommand = "INSERT INTO " + SqlSettings::USERS_TABLE + "(email, password, name) VALUES('" +
		user.email + "', '" +
		user.password + "', '" +
		user.name + "');";

	mysql_query(&m_mysql, insertCommand.c_str());

	// Проверка корректного сохранения данных (без ошибки = 0)
	if (mysql_errno(&m_mysql))
	{
		errorMySQL(toScreen, "registration: The user with the username " + user.email + " is not registered.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}
	else
	{
		printInfo("registration: The user with the username " + user.email + " is registered.", toScreen);

		return DbMySQL::CREATED;
	}
}

// Проверяет, что текущий пользователь зарегистрирован и возвращает информацию по нему
// UserData& user - параметр вывода
int DbMySQL::checkRegGetData(UserData& user)
{
	// Выбираем БД с данными пользователей
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// Проверяем наличие почты в зарегистрированных
	std::string commandGetPassword = "SELECT name, password, access FROM " + SqlSettings::USERS_TABLE + 
		" WHERE email='" + user.email + "';";
	
	if (mysql_query(&m_mysql, commandGetPassword.c_str()))
	{
		errorMySQL(toScreen, "checkRegGetData: Invalid query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Получаем результат запроса
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "checkRegGetData: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Сверяем пароль
	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		if (row[1] == user.password)
		{
			// Логин и пароль верные
			user.name = row[0];

			std::stringstream ss;
			try
			{
				ss << row[2]; // численное значение в строке
				ss >> user.access;

				// Освобождаем память, использованную для результирующего набора
				mysql_free_result(res);
				printInfo("checkRegGetData: Successful operation.", toScreen);

				return DbMySQL::OK;
			}
			catch (const std::exception& ex)
			{
				printInfo("checkRegGetData. Standart exception: " + std::string(ex.what()), toScreen);
			}

			mysql_free_result(res);

			return DbMySQL::INTERNAL_SERVER_ERROR;
		}
		else
		{
			// Пароль неверный
			printInfo("checkRegGetData: Invalid password.", toScreen);
			mysql_free_result(res);

			return DbMySQL::UNAUTHORIZED;
		}
	}
	else if (!mysql_eof(res))  // если была ошибка чтения из результирующего набора
	{
		errorMySQL(toScreen, "DbMySQL::checkRegGetData: Invalid fetch row.");
		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Логин не зарегистрирован
	printInfo("checkRegGetData: Invalid email.", toScreen);
	mysql_free_result(res);

	return DbMySQL::UNAUTHORIZED;
}

// Меняет уровень доступа пользователя
int DbMySQL::changeAccess(const UserData& user)
{
	// Выбираем БД с данными пользователей
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// Проверяем зарегистрирован ли пользователь
	int resultCheckReg = DbMySQL::checkReg(user.email);
	if (resultCheckReg == DbMySQL::NOT_ACCEPTABLE)
	{
		// Пользователь не зарегистрирован

		return resultCheckReg;
	}

	// Пользователь зарегистрирован, меняем уровень доступа
	std::string changeCommand = "UPDATE " + SqlSettings::USERS_TABLE + 
		" SET access='" + std::to_string(user.access) + "' WHERE email='" + user.email + "';";

	mysql_query(&m_mysql, changeCommand.c_str());
	if (mysql_errno(&m_mysql))
	{
		errorMySQL(toScreen, "registerRefresh: Invalid register query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	printInfo("registerRefresh: The access level is successfully changed.", toScreen);

	return DbMySQL::OK;
}



// Сохраняет Refresh-токен в БД (после авторизации пользователя)
int DbMySQL::registerRefresh(const std::string& email, const std::string& refreshToken)
{
	std::lock_guard<std::mutex> lock(g_mtxSqlAuth);

	// Выбираем БД с данными пользователей
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// Проверяем авторизован ли пользователь
	std::string checkCommand = "SELECT * FROM " + SqlSettings::AUTH_TABLE + " WHERE email='" + email + "';";

	// Запрос наличия пользователя среди авторизованных
	if (mysql_query(&m_mysql, checkCommand.c_str()))
	{
		errorMySQL(toScreen, "registerRefresh: Invalid check query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Результат запроса
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "registerRefresh: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}
	
	// Составляем команду в зависимости от результата запроса
	std::string refreshCommand;
	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))  // пользователь уже авторизован
	{
		refreshCommand = "UPDATE " + SqlSettings::AUTH_TABLE + 
			" SET refresh='" + refreshToken + "', auth_reg_date=NOW() WHERE email='" + email + "';";
	}
	else if (!mysql_eof(res))  // если была ошибка чтения из результирующего набора
	{
		errorMySQL(toScreen, "registerRefresh: Invalid fetch row.");

		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}
	else
	{
		// пользователь не авторизован
		refreshCommand = "INSERT INTO " + SqlSettings::AUTH_TABLE + "(email, refresh) VALUES('" + email + "', '" + refreshToken + "');";
	}

	// Освобождаем память, использованную для результирующего набора
	mysql_free_result(res);


	// Регистрируем Refresh-токен
	mysql_query(&m_mysql, refreshCommand.c_str());
	if (mysql_errno(&m_mysql))
	{
		errorMySQL(toScreen, "registerRefresh: Invalid register query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	printInfo("registerRefresh: Successful operation.", toScreen);
	return DbMySQL::CREATED;
}

// Перерегистрирует Refresh-токен, если он был выдан ранее
int DbMySQL::refreshTokens(const std::string& email, const std::string& newRefreshToken, const std::string& oldRefreshToken)
{
	std::lock_guard<std::mutex> lock(g_mtxSqlAuth);

	// Выбираем БД с данными пользователей
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// Проверяем авторизацию пользователя
	std::string checkCommand = "SELECT refresh FROM " + SqlSettings::AUTH_TABLE + " WHERE email='" + email + "';";

	// Запрос наличия пользователя среди авторизованных
	if (mysql_query(&m_mysql, checkCommand.c_str()))
	{
		errorMySQL(toScreen, "refreshTokens: Invalid check query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Результат запроса
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "refreshTokens: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		// Пользователь авторизован
		
		if (row[0] != oldRefreshToken)
		{
			// Предоставленный токен не совпадает с зарегистрированым в БД
			mysql_free_result(res);
			printInfo("refreshTokens: Incorrect Refresh token.", toScreen);

			return DbMySQL::UNAUTHORIZED;
		}

		mysql_free_result(res);

		// Регистрируем новый Refresh-токен
		std::string refreshCommand("UPDATE " + SqlSettings::AUTH_TABLE + 
			" SET refresh='" + newRefreshToken + "', auth_reg_date=NOW() WHERE email='" + email + "';");
		
		mysql_query(&m_mysql, refreshCommand.c_str());
		// Проверяем успешность внесения изменений
		if (mysql_errno(&m_mysql))
		{
			errorMySQL(toScreen, "refreshTokens: Invalid register query.");

			return DbMySQL::SERVICE_UNAVAILABLE;
		}

		printInfo("refreshTokens: Successful operation.", toScreen);

		return DbMySQL::CREATED;
	}
	else if (!mysql_eof(res))
	{
		// Ошибка чтения из результирующего набора
		errorMySQL(toScreen, "refreshTokens: Invalid fetch row.");
		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}
	else
	{
		// Пользователь не авторизован
		mysql_free_result(res);
		printInfo("refreshTokens: The user is unauthorized.", toScreen);

		return DbMySQL::UNAUTHORIZED;
	}
}



// Получение информации о пользователе по email
// UserData& user - параметр вывода
int DbMySQL::getUserDataOnEmail(UserData& user)
{
	ScreenLog toScreen;

	// Если email не передан
	if (user.email == "")
	{
		printInfo("getUserDataOnEmail: Incorrect email.", toScreen);

		return DbMySQL::INTERNAL_SERVER_ERROR;
	}

	// Выбираем БД с данными пользователей
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Проверяем наличие почты в зарегистрированных
	std::string commandGetPassword = "SELECT name, access FROM " + SqlSettings::USERS_TABLE + " WHERE email='" + user.email + "';";
	if (mysql_query(&m_mysql, commandGetPassword.c_str()))
	{
		errorMySQL(toScreen, "getUserDataOnEmail: Invalid query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Получаем результат запроса
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "getUserDataOnEmail: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Сохраняем данные из запроса
	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		// Если предоставлены не все поля
		if (mysql_num_fields(res) != 2)
		{
			printInfo("getUserDataOnEmail: Invalid num fields.", toScreen);
			
			// Освобождаем память, использованную для результирующего набора
			mysql_free_result(res);

			return DbMySQL::INTERNAL_SERVER_ERROR;
		}
		
		// Получаем значения из БД
		user.name = row[0];
		std::stringstream ss;
		try
		{
			ss << row[1];
			ss >> user.access;

			mysql_free_result(res);
			printInfo("getUserDataOnEmail: Successful operation.", toScreen);

			return DbMySQL::OK;
		}
		catch (const std::exception& ex)
		{
			printInfo("getUserDataOnEmail. Standart exception: " + std::string(ex.what()), toScreen);
		}

		mysql_free_result(res);

		return DbMySQL::INTERNAL_SERVER_ERROR;
	}
	else if (!mysql_eof(res))
	{
		// Если была ошибка чтения из результирующего набора
		errorMySQL(toScreen, "getUserDataOnEmail: Invalid fetch row.");
		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Логин не зарегистрирован
	printInfo("getUserDataOnEmail: Invalid email.", toScreen);
	mysql_free_result(res);

	return DbMySQL::UNAUTHORIZED;
}

// Получение списка всех зарегистрированных организаций
// std::vector<Organization>& organizations - параметр вывода
int DbMySQL::getOrganizations(std::vector<Organization>& organizations)
{
	// Выбираем БД с данными организаций
	if (!selectDB(m_settings.orgDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// Запрос списка организаций
	std::string getOrgCommand = "SELECT * FROM " + SqlSettings::ORG_TABLE;
	if (mysql_query(&m_mysql, getOrgCommand.c_str()))
	{
		errorMySQL(toScreen, "getOrganizations: Invalid check query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Результат запроса
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "getOrganizations: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Проходим по строкам выборки
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res)))
	{
		Organization org;
		std::stringstream ss;
		ss << row[0];
		ss >> org.id;
		org.name = row[1];
		organizations.push_back(org);
	}

	// Проверяем достигнут ли конец результирующего набора
	if (!mysql_eof(res))
	{
		errorMySQL(toScreen, "getOrganizations: Invalid fetch row.");

		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// Освобождаем память, использованную для результирующего набора
	mysql_free_result(res);
	printInfo("getOrganizations: Successful operation.", toScreen);

	return DbMySQL::OK;
}
