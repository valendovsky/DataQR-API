#include "AuthToken.h"

#include <string>
#include <random>
#include <vector>
#include <exception>

#include <nlohmann/json.hpp>
#include <cryptopp/base64.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/md5.h>

#include "Constants.h"
#include "Structs.h"
#include "TokenSettings.h"
#include "IWriteLog.h"
#include "ScreenLog.h"
#include "DateTime.h"


// Инициализируем статические члены класса
std::random_device AuthToken::s_rd;
std::mt19937 AuthToken::s_gen(s_rd());
std::uniform_int_distribution<> AuthToken::s_dis(0, 15);
std::uniform_int_distribution<> AuthToken::s_dis2(8, 11);



// Метод логирования
void AuthToken::printInfo(const std::string& message, IWriteLog& typeLog)
{
	typeLog.writeLog("INFO AuthToken " + message);
}



// Возвращает псевдо uuid
std::string AuthToken::getUuidV4()
{
	std::stringstream ss;
	int iter;
	ss << std::hex;
	for (iter = 0; iter < 8; ++iter)
	{
		ss << s_dis(s_gen);
	}

	ss << "-";
	for (iter = 0; iter < 4; ++iter)
	{
		ss << s_dis(s_gen);
	}

	ss << "-4";  // версия
	for (iter = 0; iter < 3; ++iter)
	{
		ss << s_dis(s_gen);
	}

	ss << "-";
	ss << s_dis2(s_gen);  // вариант
	for (iter = 0; iter < 3; ++iter)
	{
		ss << s_dis(s_gen);
	}

	ss << "-";
	for (iter = 0; iter < 12; ++iter)
	{
		ss << s_dis(s_gen);
	}

	ScreenLog toScreen;
	printInfo("getUuidV4: Uuid created.", toScreen);

	return ss.str();
}

// Возвращает строку, кодированную методом base64url
std::string AuthToken::base64UrlEncode(const std::string& decoded)
{
	ScreenLog toScreen;
	std::string encoded;

	CryptoPP::Base64URLEncoder encoder;
	encoder.Put((CryptoPP::byte*)decoded.data(), decoded.size());
	encoder.MessageEnd();

	CryptoPP::word64 size = encoder.MaxRetrievable();
	if (size)
	{
		encoded.resize(size);
		encoder.Get((CryptoPP::byte*)&encoded[0], encoded.size());

		printInfo("base64UrlEncode: Successful encoding.", toScreen);
	}
	else
	{
		encoded = ServerConstants::NONE;

		printInfo("base64UrlEncode: Failed encoding.", toScreen);
	}

	return encoded;
}

// Возвращает декодированную строку в зависимости от предоставленного метода декодирования
std::string AuthToken::base64Base64UrlDecode(const std::string& encoded, CryptoPP::BaseN_Decoder& decoder)
{
	ScreenLog toScreen;
	std::string decoded;

	decoder.Put((CryptoPP::byte*)encoded.data(), encoded.size());
	decoder.MessageEnd();

	CryptoPP::word64 size = decoder.MaxRetrievable();
	if (size && size <= SIZE_MAX)
	{
		decoded.resize(size);
		decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size());

		printInfo("base64Base64UrlDecode: Successful decoding.", toScreen);
	}
	else
	{
		decoded = ServerConstants::NONE;

		printInfo("base64Base64UrlDecode: Failed dcoding.", toScreen);
	}

	return decoded;
}

// Возвращает строку декодированную методом base64url
std::string AuthToken::base64UrlDecode(const std::string& encoded)
{
	ScreenLog toScreen;
	printInfo("- base64UrlDecode RUN.", toScreen);
	CryptoPP::Base64URLDecoder decoder;

	return base64Base64UrlDecode(encoded, decoder);
}

// Возвращает строку декодированную методом base64
std::string AuthToken::base64Decode(const std::string& encoded)
{
	ScreenLog toScreen;
	printInfo("- base64Decode RUN.", toScreen);
	CryptoPP::Base64Decoder decoder;

	return base64Base64UrlDecode(encoded, decoder);
}

// Возвращает сигнатуру хешированную методом HMAC-SHA256
std::string AuthToken::createSignatureHS256(const std::string& headerPayload, const std::string& key)
{
	ScreenLog toScreen;
	printInfo("- createSignatureHS256 RUN.", toScreen);
	std::string mac;

	try
	{
		CryptoPP::HMAC< CryptoPP::SHA256 > hmac((CryptoPP::byte*)key.c_str(), key.size());

		CryptoPP::StringSource ss2(headerPayload, true,
			new CryptoPP::HashFilter(hmac,
				new CryptoPP::StringSink(mac)
			) // HashFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		printInfo("createSignatureHS256. Standart exception: " + std::string(e.what()), toScreen);

		mac = ServerConstants::NONE;
	}

	// Если произошла ошибка хеширования
	if (mac == ServerConstants::NONE)
	{
		printInfo("createSignatureHS256: Failed hashing.", toScreen);
		return ServerConstants::NONE;
	}

	// Кодируем сигнатуру base64url
	std::string signature = base64UrlEncode(mac);


	return signature;
}

// Возвращает строку хешированную алгоритмом md5
std::string AuthToken::hashMd5(const std::string& password)
{
	ScreenLog toScreen;
	printInfo("- hashMd5 RUN.", toScreen);

	std::string hashPassword;
	CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashPassword));

	std::string digest;

	CryptoPP::Weak1::MD5 hash;
	hash.Update((const CryptoPP::byte*)&password[0], password.size());
	digest.resize(hash.DigestSize());
	hash.Final((CryptoPP::byte*)&digest[0]);

	CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));

	return hashPassword;
}



// Возвращает СТРОКОВЫЕ атрибуты из Payload JWT-токена
std::string AuthToken::getStringFromPayload(const std::string& jwtToken, const std::string& attributeName)
{
	ScreenLog toScreen;
	printInfo("- getStringFromPayload RUN.", toScreen);

	// Получаем payload токена
	int startPayload = jwtToken.find(".") + 1;
	std::string encodedPayload(jwtToken.begin() + startPayload, jwtToken.begin() + jwtToken.find(".", startPayload));
	std::string decodedPayload = base64UrlDecode(encodedPayload);

	// Выделяем из payload атрибут attributeName
	try
	{
		nlohmann::json parsed;
		parsed = nlohmann::json::parse(decodedPayload);
		std::string attributeValue = parsed.at(attributeName);
		printInfo("getStringFromPayload: The attribute has been successfully selected.", toScreen);

		return attributeValue;
	}
	catch (const std::exception& ex)
	{
		printInfo("getStringFromPayload. Standart exception: " + std::string(ex.what()), toScreen);
	}

	printInfo("getStringFromPayload: Failed to selected the attribute.", toScreen);

	return ServerConstants::NONE;
}

// Возвращает ЧИСЛЕННЫЕ атрибуты из Payload JWT-токена
// В случае ошибки возвращает 0
int AuthToken::getIntFromPayload(const std::string& jwtToken, const std::string& attributeName)
{
	ScreenLog toScreen;
	printInfo("- getIntFromPayload RUN.", toScreen);

	// Получаем payload токена
	int startPayload = jwtToken.find(".") + 1;
	std::string encodedPayload(jwtToken.begin() + startPayload, jwtToken.begin() + jwtToken.find(".", startPayload));
	std::string decodedPayload = base64UrlDecode(encodedPayload);

	// Выделяем из payload атрибут attributeName
	try
	{
		nlohmann::json parsed;
		parsed = nlohmann::json::parse(decodedPayload);
		int attributeValue = parsed.at(attributeName);
		printInfo("getIntFromPayload: The attribute has been successfully selected.", toScreen);

		return attributeValue;
	}
	catch (const std::exception& ex)
	{
		printInfo("getIntFromPayload. Standart exception: " + std::string(ex.what()), toScreen);
	}

	printInfo("getIntFromPayload: Failed to selected the attribute.", toScreen);

	return 0;
}



// Создаёт JWT токен на основе данных о пользователе
std::string AuthToken::createJwt(const UserData& user)
{
	ScreenLog toScreen;
	printInfo("- createJwt RUN.", toScreen);

	// Хедер для JWT
	nlohmann::json headerJson;
	headerJson[TokenSettings::JWT_ALG] = TokenSettings::JWT_ALG_HS256;
	headerJson[TokenSettings::JWT_TYP] = TokenSettings::JWT_TYP_JWT;

	// Кодируем заголовок base64url
	std::string headerStr = base64UrlEncode(headerJson.dump());

	// Если предоставлен пустой объект user
	if (user.name.empty() || user.email.empty())
	{
		printInfo("createJwt: The user name or the user email is empty.", toScreen);

		return ServerConstants::NONE;
	}

	// Pyaload для JWT
	nlohmann::json payloadJson;
	payloadJson[ServerConstants::NAME] = user.name;
	payloadJson[ServerConstants::EMAIL] = user.email;
	payloadJson[ServerConstants::ACCESS_LAYER] = user.access;
	payloadJson[TokenSettings::JWT_ISS] = TokenSettings::JWT_ISS_NAME;

	DateTime time;
	// Время создания токена
	auto iatTime = time.getTimeNow();
	payloadJson[TokenSettings::JWT_IAT] = iatTime;

	// Время окончания действия токена
	payloadJson[TokenSettings::JWT_EXP] = time.getExpTimeMin(TokenSettings::JWT_EXP_TIME, iatTime);

	// Кодируем заголовок base64url
	std::string payloadStr = base64UrlEncode(payloadJson.dump());

	// Получаем кодированную base64url сигнатуру
	std::string signature = createSignatureHS256(headerStr + "." + payloadStr, TokenSettings::KEY_JWT);

	// Проверка успешности кодирования
	if (headerStr == ServerConstants::NONE || 
		payloadStr == ServerConstants::NONE || 
		signature == ServerConstants::NONE)
	{
		printInfo("createJwt: Failed encoding.", toScreen);

		return ServerConstants::NONE;
	}

	printInfo("createJwt: Token was created successfully.", toScreen);

	return headerStr + "." + payloadStr + "." + signature;
}

// Создаёт Refresh-токен
std::string AuthToken::createRefresh(const std::string& jwtToken)
{
	ScreenLog toScreen;
	printInfo("- createRefresh RUN.", toScreen);

	// Если JWT-токен слишком короткий для подписи Refresh-токена
	if (jwtToken.length() < TokenSettings::JWT_REFRESH_END)
	{
		printInfo("createRefresh: JWT is too short.", toScreen);

		return ServerConstants::NONE;
	}

	// Вставляем в конец Refresh-токена окончание JWT для связки
	std::string end(jwtToken.end() - TokenSettings::JWT_REFRESH_END, jwtToken.end());

	// Используем uuid в качестве случайного значения
	std::string middle = base64UrlEncode(getUuidV4());

	// Время окончания действия Refresh-токена
	DateTime time;
	std::string begin = base64UrlEncode(std::to_string(time.getRefreshTimeHour(TokenSettings::REFRESH_EXP_TIME)));

	// Проверка успешности кодирования
	if (middle == ServerConstants::NONE || begin == ServerConstants::NONE)
	{
		printInfo("createRefresh: Failed encoding.", toScreen);

		return ServerConstants::NONE;
	}

	printInfo("createRefresh: Successful operation.", toScreen);

	// Size refresh token: 14 + . + 48 + 6 = 69
	return begin + "." + middle + end;
}



// Проверяет JWT-токен на целостность
bool AuthToken::checkJwt(const std::string& jwtToken)
{
	ScreenLog toScreen;
	printInfo("- checkJwt RUN.", toScreen);

	// Разделяем токен на состовляющие
	int beginDelimPosition = 0;
	int endDelimPosition;
	std::vector<std::string> elementJwt;
	
	// Получаем header и payload
	for (int round = 0; round < 2; ++round)
	{
		endDelimPosition = jwtToken.find(".", beginDelimPosition);
		if (endDelimPosition == std::string::npos || endDelimPosition == beginDelimPosition)
		{
			printInfo("checkJwt: Incorrect JWT.", toScreen);

			return false;
		}
		elementJwt.push_back(jwtToken.substr(beginDelimPosition, endDelimPosition - beginDelimPosition));
		beginDelimPosition = endDelimPosition + 1;
	}

	// Получаем сигнатуру из остатков строки
	elementJwt.push_back(jwtToken.substr(beginDelimPosition, jwtToken.length() - beginDelimPosition));

	// Создаём сигнатуру для полученных header'a и payload'a
	std::string testSignature = createSignatureHS256(elementJwt[0] + "." + elementJwt[1], TokenSettings::KEY_JWT);

	// Сверяем сигнатуры
	if (elementJwt[2] == testSignature)
	{
		printInfo("checkJwt: Valid JWT.", toScreen);

		return true;
	}
	else
	{
		printInfo("checkJwt: Invalid JWT.", toScreen);

		return false;
	}
}

// Проверяет JWT и Refresh токены на сопряженность
bool AuthToken::checkJwtRefresh(const std::string& jwtToken, const std::string& refreshToken)
{
	ScreenLog toScreen;
	printInfo("- checkJwtRefresh RUN.", toScreen);

	// Если токены слишком короткие
	if (jwtToken.length() < TokenSettings::JWT_REFRESH_END || refreshToken.length() < TokenSettings::JWT_REFRESH_END)
	{
		printInfo("checkJwtRefresh: Incorrect access tokens.", toScreen);

		return false;
	}

	// Последние символы в количестве JWT_REFRESH_END должны быть одинаковые
	if (std::string(jwtToken.end() - TokenSettings::JWT_REFRESH_END, jwtToken.end()) ==
		std::string(refreshToken.end() - TokenSettings::JWT_REFRESH_END, refreshToken.end()))
	{
		printInfo("checkJwtRefresh: Valid access tokens.", toScreen);

		return true;
	}
	else
	{
		printInfo("checkJwtRefresh: Invalid access tokens.", toScreen);

		return false;
	}
}

// Проверяет срок действия Refresh-токена на актуальность
bool AuthToken::checkRefreshExp(const std::string& refreshToken)
{
	ScreenLog toScreen;
	printInfo("- checkRefreshExp RUN.", toScreen);

	// Получаем координаты временной метки
	int positionEndTime = refreshToken.find(".");
	if (positionEndTime == std::string::npos || positionEndTime == 0)
	{
		// Временная метка отсутствует
		printInfo("checkRefreshExp: Incorrect time label.", toScreen);

		return false;
	}

	// Декодируем временную метку
	std::string decoded = base64UrlDecode(refreshToken.substr(0, positionEndTime));
	if (decoded == ServerConstants::NONE)
	{
		// Строка некорректная
		printInfo("checkRefreshExp: Invalid time label.", toScreen);

		return false;
	}

	// Конвертируем строку во временной формат
	time_t timeEnd;
	try
	{
		std::stringstream ss;
		ss << decoded;
		ss >> timeEnd;
	}
	catch (const std::exception& ex)
	{
		printInfo("checkRefreshExp. Standart exception: " + std::string(ex.what()), toScreen);

		return false;
	}

	// Сравниваем время жизни токена с текущим
	DateTime time;
	time_t timeNow = time.getTimeNow();
	if (timeNow > timeEnd)
	{
		// Refresh-токен просрочен
		printInfo("checkRefreshExp: Expired Refresh token.", toScreen);

		return false;
	}
	else
	{
		printInfo("checkRefreshExp: Valid Refresh token.", toScreen);

		return true;
	}
}

// Проверяет срок действия JWT-токена на актуальность
bool AuthToken::checkJwtCheckExp(const std::string& jwtToken)
{
	ScreenLog toScreen;
	printInfo("- checkJwtCheckExp RUN.", toScreen);

	// Проверяем JWT на корректность
	if (!checkJwt(jwtToken))
	{
		printInfo("checkJwtCheckExp: Incorrect JWT.", toScreen);

		return false;
	}

	// Получаем срок жизни JWT
	time_t jwtExp = getIntFromPayload(jwtToken, TokenSettings::JWT_EXP);
	if (!jwtExp)
	{
		printInfo("checkJwtCheckExp: Incorrect time label.", toScreen);

		return false;
	}

	// Получаем текущее время
	DateTime time;
	time_t timeNow = time.getTimeNow();

	// Токен просрочен
	if (jwtExp < timeNow)
	{
		printInfo("checkJwtCheckExp: Expired JWT.", toScreen);

		return false;
	}

	printInfo("checkJwtCheckExp: Valid JWT.", toScreen);

	return true;
}



// Провереят предоставленный JWT-токен и возвращает email указанный в нём
std::string AuthToken::checkJwtGetEmail(const std::string& jwtToken)
{
	ScreenLog toScreen;
	printInfo("- checkJwtGetEmail RUN.", toScreen);

	// JWT-токен невалидный
	if (!checkJwt(jwtToken))
	{
		printInfo("checkJwtGetEmail: Invalid JWT.", toScreen);
		return ServerConstants::NONE;
	}

	return getStringFromPayload(jwtToken, ServerConstants::EMAIL);
}



// Возвращает email указаный в JWT-токене
std::string AuthToken::getJwtEmail(const std::string& jwtToken)
{
	ScreenLog toScreen;
	printInfo("- getJwtEmail RUN.", toScreen);

	return getStringFromPayload(jwtToken, ServerConstants::EMAIL);
}

// Возвращает уровень доступа пользователя указаный вJWT-токене
int AuthToken::getJwtAccess(const std::string& jwtToken)
{
	ScreenLog toScreen;
	printInfo("- getJwtAccess RUN.", toScreen);

	return getIntFromPayload(jwtToken, ServerConstants::ACCESS_LAYER);
}
