#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <string>


// Литеральные константы сервера
namespace ServerConstants
{
	const std::string NONE          = "none";
	const std::string EMAIL         = "email";
	const std::string NAME          = "name";
	const std::string PASSWORD      = "password";
	const std::string ACCESS_LAYER  = "access";
	const std::string ORG_ID        = "id";
	const std::string BASIC_PREFIX  = "Basic ";
	const std::string BEARER_PREFIX = "Bearer ";

}

#endif // !CONSTANTS_H
