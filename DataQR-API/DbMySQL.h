#ifndef DBMYSQL_H
#define DBMYSQL_H

#include <mysql.h>

#include <string>
#include <vector>

#include "SqlSettings.h"
#include "Structs.h"
#include "IWriteLog.h"
#include "ScreenLog.h"


// ����� ��� ������ � ������ ������ ������� MySQL
class DbMySQL
{
private:
	// ���������� ����������
	MYSQL m_mysql;

	// ���������� ����������� � ��
	MySQLSettings m_settings;
	bool m_initialization;
	bool m_connection;


public:
	// �����������
	DbMySQL(const MySQLSettings& sqlSettings) 
		: m_settings(sqlSettings),
		m_initialization(false),
		m_connection(false)
	{
		ScreenLog toScreen;

		if (initialization())
		{
			if (!connect(m_settings.usersDB))
			{
				printInfo("CRITICAL ERROR initConnectMySQL: Failed connect.", toScreen);
			}
			else
			{
				printInfo("DbMySQL: Successful initialization.", toScreen);
			}
		}
		else
		{
			printInfo("CRITICAL ERROR initConnectMySQL: Failed initialization.", toScreen);
		}
	}

	// ����������
	~DbMySQL()
	{
		if (m_initialization && m_connection)
		{
			mysql_close(&m_mysql);
		}
	}

	enum HTTP_STATUS
	{
		OK = 200,
		CREATED = 201,
		UNAUTHORIZED = 401,
		NOT_ACCEPTABLE = 406,
		CONFLICT = 409,
		INTERNAL_SERVER_ERROR = 500,
		SERVICE_UNAVAILABLE = 503,

	};

	// ������������� �����������
	bool initialization();
	// ������������ ���������� � ��
	bool connect(const std::string& nameDB);
	// �������� ����������� � ��
	bool checkConnect();
	
	// ������ � ������� �������������
	int registration(const UserData& user);
	int checkRegGetData(UserData& user);
	int changeAccess(const UserData& user);
	
	// ������ � Refresh-��������
	int registerRefresh(const std::string& email, const std::string& refreshToken);
	int refreshTokens(const std::string& email, const std::string& newRefreshToken, const std::string& oldRefreshToken);

	// �������
	int getUserDataOnEmail(UserData& user);
	int getOrganizations(std::vector<Organization>& organizations);

private:
	// ����� ������ � ����������
	void printInfo(const std::string& message, IWriteLog& typeLog);
	void errorMySQL(IWriteLog& typeLog, const std::string& message);
	
	// ��������� �������
	bool getInit() { return m_initialization; }
	bool getConnect() { return m_connection; }

	bool selectDB(const std::string& nameDB);
	int checkReg(const std::string& userEmail);
};

#endif // !DBMYSQL_H
