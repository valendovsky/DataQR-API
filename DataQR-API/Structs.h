#ifndef STRUCTS_H
#define STRUCTS_H

#include <string>


// ������ ������������
struct UserData
{
	std::string email;
	std::string password;
	std::string name;
	int access = 3;
};


// ������ �����������
struct Organization
{
	int id;
	std::string name;
};

#endif // !STRUCTS_H
