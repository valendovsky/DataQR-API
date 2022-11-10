#ifndef SERVERSETTINGS_H
#define SERVERSETTINGS_H

#include <string>


// Уровни доступа пользователей
namespace AccessLayer
{
	enum UserLayer
	{
		MIN_LAYER = 1,
		ADMIN = 1,
		VIP_USER = 2,
		USER = 3,
		MAX_LAYER = 3
	};
}


// Настройки подключения сервера
namespace ServerSettings
{
	const std::string FILE_SQL_SETTINGS = "../source/sql_settings.txt";    // файл настроект доступа к SQL
	const std::string REALM             = "DataQR-API";
	const std::string PREFIX_QR_CODE    = "DataQR-API.com/project?code=";
	const std::string PREFIX_QR_FILE    = "../source/QRcodeFile";

	const int PORT                = 9090;
	const unsigned int THREAD_NUM = 4;     // Количество потоков для работы
	const int MIN_EMAIL_SIZE      = 6;
	const int MAX_EMAIL_SIZE      = 30;
	const int MIN_PASSWORD_SIZE   = 8;
	const int MAX_PASSWORD_SIZE   = 32;
	const int MAX_NAME_SIZE       = 30;
	const int BASIC_LENGTH        = 6;     // "Basic " = 6
	const int BEARER_LENGTH       = 7;     // "Bearer " = 7
	const int ENCODED_STR_SIZE    = 5;

	// Эндпоинты сервера
	const std::string API_REGISTER      = "/api/register";
	const std::string API_LOGIN         = "/api/login";
	const std::string API_REFRESH_TOKEN = "/api/refresh-token";
	const std::string API_PROFILE       = "/api/profile";
	const std::string API_ACCESS        = "/api/access";
	const std::string API_ORGANIZATIONS = "/api/organizations";
	const std::string API_ENCODE        = "/api/encode";
	const std::string API_DECODE        = "/api/decode";

}

#endif // !SERVERSETTINGS_H
