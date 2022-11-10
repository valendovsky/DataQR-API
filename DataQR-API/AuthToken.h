#ifndef AUTHTOKEN_H
#define AUTHTOKEN_H

#include <string>
#include <random>

#include <cryptopp/base64.h>

#include "Structs.h"
#include "IWriteLog.h"


// Класс для работы с токенами доступа и заголовками авторизации
class AuthToken
{
private:
	// ГПСЧ
	static std::random_device s_rd;
	static std::mt19937 s_gen;
	// Отрезки распределения значений
	static std::uniform_int_distribution<> s_dis;
	static std::uniform_int_distribution<> s_dis2;

public:
	AuthToken(){}

	std::string base64UrlEncode(const std::string& decoded);
	std::string base64UrlDecode(const std::string& encoded);
	std::string base64Decode(const std::string& encoded);
	std::string hashMd5(const std::string& password);

	std::string createJwt(const UserData& user);
	std::string createRefresh(const std::string& jwtToken);

	bool checkJwt(const std::string& jwtToken);
	bool checkJwtRefresh(const std::string& jwtToken, const std::string& refreshToken);
	bool checkRefreshExp(const std::string& refreshToken);
	bool checkJwtCheckExp(const std::string& jwtToken);
	
	std::string checkJwtGetEmail(const std::string& jwtToken);

	std::string getJwtEmail(const std::string& jwtToken);
	int getJwtAccess(const std::string& jwtToken);

private:
	void printInfo(const std::string& message, IWriteLog& typeLog);

	std::string getUuidV4();
	std::string base64Base64UrlDecode(const std::string& encoded, CryptoPP::BaseN_Decoder& decoder);
	std::string createSignatureHS256(const std::string& headerPayload, const std::string& key);
	
	std::string getStringFromPayload(const std::string& jwtToken, const std::string& attributeName);
	int getIntFromPayload(const std::string& jwtToken, const std::string& attributeName);

};

#endif // !AUTHTOKEN_H
