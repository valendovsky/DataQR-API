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


// ����� ����������� ����������
void DbMySQL::printInfo(const std::string& message, IWriteLog& typeLog)
{
	typeLog.writeLog("INFO DbMySQL " + message);
}

// ����� �������� ������ MySQL � �������������� ����������
void DbMySQL::errorMySQL(IWriteLog& typeLog, const std::string& message = "")
{
	if (message != "")
	{
		printInfo(message, typeLog);
	}

	printInfo("STANDART ERROR MySQL: " + std::string(mysql_error(&m_mysql)), typeLog);
}



// �������������� ����������
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

// ������������� ���������� � ��
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

// ��������� ������������� � �����������
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



// ������ �������� ��
bool DbMySQL::selectDB(const std::string& nameDB)
{
	// �������� ����������� � MySQL
	if (!checkConnect())
	{
		return false;
	}

	ScreenLog toScreen;

	// ��� ������ ������������ �� ���������� 0
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

// ��������� ��������������� �� ������������ � �������
int DbMySQL::checkReg(const std::string& userEmail)
{
	// �������� �� � ������� �������������
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// ��������� ��������������� �� ������������
	std::string checkCommand = "SELECT * FROM " + SqlSettings::USERS_TABLE + " WHERE email='" + userEmail + "';";
	if (mysql_query(&m_mysql, checkCommand.c_str()))
	{
		errorMySQL(toScreen, "checkReg: Invalid query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ��������� �������
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "checkReg: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		// email ���������������
		printInfo("checkReg: The user with the email " + userEmail + " is registered.", toScreen);

		// ����������� ������, �������������� ��� ��������������� ������
		mysql_free_result(res);

		return DbMySQL::CONFLICT;
	}
	else if (!mysql_eof(res))
	{
		// ���� ���� ������ ������ �� ��������������� ������
		errorMySQL(toScreen, "checkReg: Invalid fetch row.");

		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ������������ �� ���������������
	printInfo("checkReg: The user with the email " + userEmail + " isn't registered.", toScreen);
	
	// ����������� ������, �������������� ��� ��������������� ������
	mysql_free_result(res);

	return DbMySQL::NOT_ACCEPTABLE;
}



// ������������ ������������ � ��, �������� �� ����������������� �� ������������ �����
int DbMySQL::registration(const UserData& user)
{
	std::lock_guard<std::mutex> lock(g_mtxSqlReg);

	// �������� �� � ������� �������������
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// ��������� ��������������� �� ������������
	int resultCheckReg = DbMySQL::checkReg(user.email);
	if (resultCheckReg != DbMySQL::NOT_ACCEPTABLE)
	{
		// ������������ ��������������� ��� ���-�� ����� �� ���

		return resultCheckReg;
	}

	// ������������ �� ���������������, ��������� ��� � ��
	std::string insertCommand = "INSERT INTO " + SqlSettings::USERS_TABLE + "(email, password, name) VALUES('" +
		user.email + "', '" +
		user.password + "', '" +
		user.name + "');";

	mysql_query(&m_mysql, insertCommand.c_str());

	// �������� ����������� ���������� ������ (��� ������ = 0)
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

// ���������, ��� ������� ������������ ��������������� � ���������� ���������� �� ����
// UserData& user - �������� ������
int DbMySQL::checkRegGetData(UserData& user)
{
	// �������� �� � ������� �������������
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// ��������� ������� ����� � ������������������
	std::string commandGetPassword = "SELECT name, password, access FROM " + SqlSettings::USERS_TABLE + 
		" WHERE email='" + user.email + "';";
	
	if (mysql_query(&m_mysql, commandGetPassword.c_str()))
	{
		errorMySQL(toScreen, "checkRegGetData: Invalid query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// �������� ��������� �������
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "checkRegGetData: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ������� ������
	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		if (row[1] == user.password)
		{
			// ����� � ������ ������
			user.name = row[0];

			std::stringstream ss;
			try
			{
				ss << row[2]; // ��������� �������� � ������
				ss >> user.access;

				// ����������� ������, �������������� ��� ��������������� ������
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
			// ������ ��������
			printInfo("checkRegGetData: Invalid password.", toScreen);
			mysql_free_result(res);

			return DbMySQL::UNAUTHORIZED;
		}
	}
	else if (!mysql_eof(res))  // ���� ���� ������ ������ �� ��������������� ������
	{
		errorMySQL(toScreen, "DbMySQL::checkRegGetData: Invalid fetch row.");
		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ����� �� ���������������
	printInfo("checkRegGetData: Invalid email.", toScreen);
	mysql_free_result(res);

	return DbMySQL::UNAUTHORIZED;
}

// ������ ������� ������� ������������
int DbMySQL::changeAccess(const UserData& user)
{
	// �������� �� � ������� �������������
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// ��������� ��������������� �� ������������
	int resultCheckReg = DbMySQL::checkReg(user.email);
	if (resultCheckReg == DbMySQL::NOT_ACCEPTABLE)
	{
		// ������������ �� ���������������

		return resultCheckReg;
	}

	// ������������ ���������������, ������ ������� �������
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



// ��������� Refresh-����� � �� (����� ����������� ������������)
int DbMySQL::registerRefresh(const std::string& email, const std::string& refreshToken)
{
	std::lock_guard<std::mutex> lock(g_mtxSqlAuth);

	// �������� �� � ������� �������������
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// ��������� ����������� �� ������������
	std::string checkCommand = "SELECT * FROM " + SqlSettings::AUTH_TABLE + " WHERE email='" + email + "';";

	// ������ ������� ������������ ����� ��������������
	if (mysql_query(&m_mysql, checkCommand.c_str()))
	{
		errorMySQL(toScreen, "registerRefresh: Invalid check query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ��������� �������
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "registerRefresh: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}
	
	// ���������� ������� � ����������� �� ���������� �������
	std::string refreshCommand;
	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))  // ������������ ��� �����������
	{
		refreshCommand = "UPDATE " + SqlSettings::AUTH_TABLE + 
			" SET refresh='" + refreshToken + "', auth_reg_date=NOW() WHERE email='" + email + "';";
	}
	else if (!mysql_eof(res))  // ���� ���� ������ ������ �� ��������������� ������
	{
		errorMySQL(toScreen, "registerRefresh: Invalid fetch row.");

		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}
	else
	{
		// ������������ �� �����������
		refreshCommand = "INSERT INTO " + SqlSettings::AUTH_TABLE + "(email, refresh) VALUES('" + email + "', '" + refreshToken + "');";
	}

	// ����������� ������, �������������� ��� ��������������� ������
	mysql_free_result(res);


	// ������������ Refresh-�����
	mysql_query(&m_mysql, refreshCommand.c_str());
	if (mysql_errno(&m_mysql))
	{
		errorMySQL(toScreen, "registerRefresh: Invalid register query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	printInfo("registerRefresh: Successful operation.", toScreen);
	return DbMySQL::CREATED;
}

// ���������������� Refresh-�����, ���� �� ��� ����� �����
int DbMySQL::refreshTokens(const std::string& email, const std::string& newRefreshToken, const std::string& oldRefreshToken)
{
	std::lock_guard<std::mutex> lock(g_mtxSqlAuth);

	// �������� �� � ������� �������������
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// ��������� ����������� ������������
	std::string checkCommand = "SELECT refresh FROM " + SqlSettings::AUTH_TABLE + " WHERE email='" + email + "';";

	// ������ ������� ������������ ����� ��������������
	if (mysql_query(&m_mysql, checkCommand.c_str()))
	{
		errorMySQL(toScreen, "refreshTokens: Invalid check query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ��������� �������
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "refreshTokens: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		// ������������ �����������
		
		if (row[0] != oldRefreshToken)
		{
			// ��������������� ����� �� ��������� � ����������������� � ��
			mysql_free_result(res);
			printInfo("refreshTokens: Incorrect Refresh token.", toScreen);

			return DbMySQL::UNAUTHORIZED;
		}

		mysql_free_result(res);

		// ������������ ����� Refresh-�����
		std::string refreshCommand("UPDATE " + SqlSettings::AUTH_TABLE + 
			" SET refresh='" + newRefreshToken + "', auth_reg_date=NOW() WHERE email='" + email + "';");
		
		mysql_query(&m_mysql, refreshCommand.c_str());
		// ��������� ���������� �������� ���������
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
		// ������ ������ �� ��������������� ������
		errorMySQL(toScreen, "refreshTokens: Invalid fetch row.");
		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}
	else
	{
		// ������������ �� �����������
		mysql_free_result(res);
		printInfo("refreshTokens: The user is unauthorized.", toScreen);

		return DbMySQL::UNAUTHORIZED;
	}
}



// ��������� ���������� � ������������ �� email
// UserData& user - �������� ������
int DbMySQL::getUserDataOnEmail(UserData& user)
{
	ScreenLog toScreen;

	// ���� email �� �������
	if (user.email == "")
	{
		printInfo("getUserDataOnEmail: Incorrect email.", toScreen);

		return DbMySQL::INTERNAL_SERVER_ERROR;
	}

	// �������� �� � ������� �������������
	if (!selectDB(m_settings.usersDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ��������� ������� ����� � ������������������
	std::string commandGetPassword = "SELECT name, access FROM " + SqlSettings::USERS_TABLE + " WHERE email='" + user.email + "';";
	if (mysql_query(&m_mysql, commandGetPassword.c_str()))
	{
		errorMySQL(toScreen, "getUserDataOnEmail: Invalid query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// �������� ��������� �������
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "getUserDataOnEmail: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ��������� ������ �� �������
	MYSQL_ROW row;
	if (row = mysql_fetch_row(res))
	{
		// ���� ������������� �� ��� ����
		if (mysql_num_fields(res) != 2)
		{
			printInfo("getUserDataOnEmail: Invalid num fields.", toScreen);
			
			// ����������� ������, �������������� ��� ��������������� ������
			mysql_free_result(res);

			return DbMySQL::INTERNAL_SERVER_ERROR;
		}
		
		// �������� �������� �� ��
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
		// ���� ���� ������ ������ �� ��������������� ������
		errorMySQL(toScreen, "getUserDataOnEmail: Invalid fetch row.");
		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ����� �� ���������������
	printInfo("getUserDataOnEmail: Invalid email.", toScreen);
	mysql_free_result(res);

	return DbMySQL::UNAUTHORIZED;
}

// ��������� ������ ���� ������������������ �����������
// std::vector<Organization>& organizations - �������� ������
int DbMySQL::getOrganizations(std::vector<Organization>& organizations)
{
	// �������� �� � ������� �����������
	if (!selectDB(m_settings.orgDB))
	{
		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	ScreenLog toScreen;

	// ������ ������ �����������
	std::string getOrgCommand = "SELECT * FROM " + SqlSettings::ORG_TABLE;
	if (mysql_query(&m_mysql, getOrgCommand.c_str()))
	{
		errorMySQL(toScreen, "getOrganizations: Invalid check query.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ��������� �������
	MYSQL_RES* res;
	if (!(res = mysql_store_result(&m_mysql)))
	{
		errorMySQL(toScreen, "getOrganizations: Invalid result.");

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// �������� �� ������� �������
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

	// ��������� ��������� �� ����� ��������������� ������
	if (!mysql_eof(res))
	{
		errorMySQL(toScreen, "getOrganizations: Invalid fetch row.");

		mysql_free_result(res);

		return DbMySQL::SERVICE_UNAVAILABLE;
	}

	// ����������� ������, �������������� ��� ��������������� ������
	mysql_free_result(res);
	printInfo("getOrganizations: Successful operation.", toScreen);

	return DbMySQL::OK;
}
