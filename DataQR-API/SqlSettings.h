#ifndef SQLSETTINGS_H
#define SQLSETTINGS_H

#include <string>


// �������� ��������� ����������� � �� MySQL
struct MySQLSettings
{
	std::string ipDB;
	std::string login;
	std::string password;
	int port;
	std::string usersDB;
	std::string orgDB;
};


// ��������� ��� ������ � MySQL
namespace SqlSettings
{
	const std::string USERS_DB    = "user_bd";        // �������� �� ��� �������� �����������
	const std::string USERS_TABLE = "users";          // ������� � ������������������� ��������������
	const std::string AUTH_TABLE  = "auth";           // ������� � refresh-��������
	const std::string ORG_DB      = "org_db";         // �������� �� ��� �������� ���������� �� ������������
	const std::string ORG_TABLE   = "organizations";  // ������� � ������������������� �������������

}

#endif // !SQLSETTINGS_H
