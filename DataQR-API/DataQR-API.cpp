// DataQR-API.cpp : Локальный REST API сервер, реализованный на основе библиотеки Restbed, 
// и использующий в качестве базы хранения данных MySQL сервер.
// 
// Функционал сервера:
// register      - регистрация пользователей
//     name
//     email
//     password
//     access layer (уровень доступа пользователя)
//         1 - администратор
//         2 - пользователь с подпиской
//         3 - пользователь без подписки
// login         - авторизация пользователей
// refresh-token - обновление токенов доступа
// profile       - информация о текущем авторизованном пользователе
// encode        - кодирование строки, кодированная строка возвращается в виде QR файла
// decode        - раскодирование строки
// organizations - список организаций
// access        - изменение уровеня доступа пользователя (для администраторов)


#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <vector>
#include <cstdlib>
#include <cctype>
#include <fstream>
#include <sstream>
#include <functional>
#include <algorithm>
#include <thread>
#include <mutex>

#include <restbed>
#include <nlohmann/json.hpp>

#include "Constants.h"
#include "ServerSettings.h"
#include "SqlSettings.h"
#include "HeaderConstants.h"
#include "Structs.h"
#include "DbMySQL.h"
#include "AuthToken.h"
#include "QRcreater.h"
#include "IWriteLog.h"
#include "ScreenLog.h"
#include "DateTime.h"


// Мютексы
std::mutex g_mtxCout;
std::mutex g_mtxSqlReg;
std::mutex g_mtxSqlAuth;

// Настройки доступа к БД
static MySQLSettings g_sqlSettings;


// Логирует события
void printInfo(const std::string& message, IWriteLog& typeLog)
{
    typeLog.writeLog(message);
}


// Получает настройки для доступа к БД
bool getSqlSettings(const std::string& fileAddress)
{
    ScreenLog toScreen;

    std::ifstream fileSQLSettings(fileAddress);
    // Если файл не открывается
    if (!fileSQLSettings.is_open())
    {
        printInfo("CRITICAL ERROR getSqlSettings: There is no SQL settings file.", toScreen);

        return false;
    }

    std::stringstream ss;
    ss << fileSQLSettings.rdbuf();
    fileSQLSettings.close();

    // Сохраняем настройки для MySQL
    try
    {
        ss >> g_sqlSettings.ipDB >> g_sqlSettings.login >> g_sqlSettings.password >> g_sqlSettings.port;
        g_sqlSettings.usersDB = SqlSettings::USERS_DB;
        g_sqlSettings.orgDB = SqlSettings::ORG_DB;

        return true;
    }
    catch (const std::exception& exp)
    {
        printInfo("CRITICAL ERROR getSqlSettings: Invalid SQL settings.", toScreen);

        return false;
    }
}

// Трансформирует символы переданной строки в строчные
// std::string& str - параметр вывода
void strToLowercase(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char ch) { return std::tolower(ch); });
}

// Возвращает json файл помещённый в строку
std::string getJsonUserDataInStr(const UserData& user)
{
    nlohmann::json jsonUserData;
    jsonUserData[ServerConstants::NAME] = user.name;
    jsonUserData[ServerConstants::EMAIL] = user.email;
    jsonUserData[ServerConstants::ACCESS_LAYER] = user.access;

    return jsonUserData.dump();
}

// Удаляет префикс в строке
// std::string& prefixStr - параметр вывода
bool deleteAuthPrefix(std::string& prefixStr, const std::string& prefix)
{
    ScreenLog toScreen;

    // Проверяем наличие префикса в строке
    size_t position = prefixStr.find(prefix);
    if (position == std::string::npos || position != 0)
    {
        printInfo("INFO deleteAuthPrefix: There is no the prefix in the string.", toScreen);

        return false;
    }
    else
    {
        // Обрезаем префикс
        prefixStr.erase(0, prefix.length());

        return true;
    }
}


// Регистрирует пользователей через JSON
void registrationJsonHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO: registrationJsonHandler RUN.", toScreen);

    // Распарсим тело запроса
    const auto request = session->get_request();
    size_t contentLength = request->get_header(HeaderConstants::CONTENT_LENGTH, 0);
    session->fetch(contentLength, [request](const std::shared_ptr<restbed::Session> session, const restbed::Bytes& body) 
        {
            ScreenLog toScreen;
            nlohmann::json parsed;
            std::multimap<std::string, std::string> userParams;

            try
            {
                parsed = nlohmann::json::parse(body.data(), body.data() + int(body.size()));
                
                // Трансформируем все символы в строчные
                std::string userEmail = parsed.at(ServerConstants::EMAIL);
                strToLowercase(userEmail);

                userParams.insert(
                    { 
                        { ServerConstants::NAME, parsed.at(ServerConstants::NAME) }, 
                        {ServerConstants::EMAIL, userEmail},
                        {ServerConstants::PASSWORD, parsed.at(ServerConstants::PASSWORD)} 
                    }
                );
            }
            catch (const std::exception& exp)
            {
                printInfo("ERROR registrationJsonHandler. Standart exception: " + std::string(exp.what()), toScreen);
            }

            // Проверка достаточности предоставленных параметров
            if (userParams.count(ServerConstants::NAME) != 1 || 
                userParams.count(ServerConstants::EMAIL) != 1 || 
                userParams.count(ServerConstants::PASSWORD) != 1)
            {
                printInfo("INFO registrationJsonHandler: Not enough parameters.", toScreen);
                session->close(restbed::BAD_REQUEST);

                return;
            }
            
            // Собираем данные о пользователе
            UserData user;
            user.name = userParams.find(ServerConstants::NAME)->second;
            user.email = userParams.find(ServerConstants::EMAIL)->second;
            user.password = userParams.find(ServerConstants::PASSWORD)->second;

            // Проверка предоставленных значений на корректность
            if (user.name == "" || 
                user.name.length() > ServerSettings::MAX_NAME_SIZE ||
                user.email.length() < ServerSettings::MIN_EMAIL_SIZE ||
                user.email.length() > ServerSettings::MAX_EMAIL_SIZE ||
                user.password.length() < ServerSettings::MIN_PASSWORD_SIZE ||
                user.password.length() > ServerSettings::MAX_PASSWORD_SIZE)
            {
                printInfo("INFO registrationJsonHandler: Invalid parameters.", toScreen);
                session->close(restbed::BAD_REQUEST);

                return;
            }

            // Хешируем пароль
            AuthToken auth;
            user.password = auth.hashMd5(user.password);

            // Регистрируем пользователя в БД
            DbMySQL mySql(g_sqlSettings);
            int httpCode = mySql.registration(user);

            // Если пользователь успешно зарегистрирован
            if (httpCode == 201)
            {
                // Возвращаем данные пользователя
                user.access = AccessLayer::USER;
                std::string bodyResponse = getJsonUserDataInStr(user);

                printInfo("INFO registrationJsonHandler: Successful registration of " + user.email, toScreen);
                session->close(restbed::CREATED, bodyResponse,
                    { 
                        {HeaderConstants::CONTENT_LENGTH, 
                        std::to_string(bodyResponse.length())},
                        {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON} 
                    }
                );

                return;
            }

            printInfo("ERROR registrationJsonHandler: Unsuccessful registration with code " + std::to_string(httpCode), toScreen);
            session->close(httpCode);
        }
    );
}

// Регистрирует пользователей через URI Query
void registrationQueryHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO registrationQueryHandler RUN", toScreen);

    // Получим данные пользователя
    auto request = session->get_request();
    std::multimap<std::string, std::string> userParams = request->get_query_parameters();

    // Проверка достаточности предоставленных параметров
    if (userParams.count(ServerConstants::NAME) != 1 || 
        userParams.count(ServerConstants::EMAIL) != 1 || 
        userParams.count(ServerConstants::PASSWORD) != 1)
    {
        printInfo("INFO registrationQueryHandler: Not enough parameters.", toScreen);
        session->close(restbed::BAD_REQUEST);

        return;
    }
    
    // Трансформируем все символы в строчные
    strToLowercase(userParams.find(ServerConstants::EMAIL)->second);

    // Собираем данные о пользователе
    UserData user;
    user.name = userParams.find(ServerConstants::NAME)->second;
    user.email = userParams.find(ServerConstants::EMAIL)->second;
    user.password = userParams.find(ServerConstants::PASSWORD)->second;

    // Проверка предоставленных значений на корректность
    if (user.name == "" ||
        user.name.length() > ServerSettings::MAX_NAME_SIZE ||
        user.email.length() < ServerSettings::MIN_EMAIL_SIZE ||
        user.email.length() > ServerSettings::MAX_EMAIL_SIZE ||
        user.password.length() < ServerSettings::MIN_PASSWORD_SIZE ||
        user.password.length() > ServerSettings::MAX_PASSWORD_SIZE)
    {
        printInfo("INFO registrationQueryHandler: Invalid parameters.", toScreen);
        session->close(restbed::BAD_REQUEST);

        return;
    }

    // Хешируем пароль
    AuthToken auth;
    user.password = auth.hashMd5(user.password);

    // Регистрируем пользователя в БД
    DbMySQL mySql(g_sqlSettings);
    int httpCode = mySql.registration(user);

    // Если пользователь успешно зарегистрирован
    if (httpCode == 201)
    {
        // Возвращаем данные пользователя
        user.access = AccessLayer::USER;
        std::string bodyResponse = getJsonUserDataInStr(user);

        printInfo("INFO registrationQueryHandler: Successful registration of " + user.email, toScreen);
        session->close(restbed::CREATED, bodyResponse,
            { 
                {HeaderConstants::CONTENT_LENGTH, 
                std::to_string(bodyResponse.length())},
                {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON}
            }
        );

        return;
    }

    printInfo("ERROR registrationQueryHandler: Unsuccessful registration with code " + std::to_string(httpCode), toScreen);
    session->close(httpCode);
}

// Не подходит ни один фильтр хендлера на регистрацию пользователя
void registrationFailedHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO: registrationFailedHandler RUN.", toScreen);

    session->close(400);
}

// Авторизовывает пользователей
void authorizationHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO: authorizationHandler RUN.", toScreen);

    // Получаем заголовок авторизации
    auto authorization = session->get_request()->get_header(HeaderConstants::AUTHORIZATION);

    // Обрезаем префикс заголовка Authorization
    if (!deleteAuthPrefix(authorization, ServerConstants::BASIC_PREFIX))
    {
        printInfo("INFO authorizationHandler: Invalid Authorization.", toScreen);
        session->close(restbed::BAD_REQUEST);

        return;
    }

    // Декодируем аутентифицирующую информацию
    AuthToken auth;
    std::string decodedAuth = auth.base64Decode(authorization);
    if (decodedAuth == ServerConstants::NONE)
    {
        printInfo("INFO authorizationHandler: The process of decoding the Authorization header is invalid.", toScreen);
        session->close(restbed::BAD_REQUEST);

        return;
    }

    // Разделяем логин и пароль
    int delim = decodedAuth.find(':');
    // Если разделитель отсутствует или отсутствуют логин или пароль
    if (delim == std::string::npos || delim == 0 || delim == decodedAuth.length() - 1)
    {
        printInfo("INFO authorizationHandler: Incorrect Authorization header.", toScreen);
        session->close(restbed::BAD_REQUEST);

        return;
    }
    UserData user;
    user.email = std::string(decodedAuth.begin(), decodedAuth.begin() + delim);
    user.password = std::string(decodedAuth.begin() + delim + 1, decodedAuth.end());

    // Проверяем достаточность длины пароля
    if (user.password.length() < ServerSettings::MIN_PASSWORD_SIZE)
    {
        printInfo("INFO authorizationHandler: The password is too short.", toScreen);
        session->close(restbed::BAD_REQUEST);

        return;
    }

    // Хешируем пароль
    user.password = auth.hashMd5(user.password);

    // Трансформируем все символы email в строчные
    strToLowercase(user.email);

    // Аутентифицируем пользователя через БД
    DbMySQL mySql(g_sqlSettings);
    int checkResult = mySql.checkRegGetData(user);
    if (checkResult == 200)
    {
        // Создаём токены доступа
        const std::string jwtToken(auth.createJwt(user));
        const std::string refreshToken(auth.createRefresh(jwtToken));

        // Проверка успешности создания токенов
        if (jwtToken == ServerConstants::NONE || refreshToken == ServerConstants::NONE)
        {
            printInfo("ERROR authorizationHandler: Error creating access tokens.", toScreen);
            session->close(restbed::SERVICE_UNAVAILABLE);

            return;
        }

        // Регистрируем refresh-токен в таблице сессий
        int refreshRegResult = mySql.registerRefresh(user.email, refreshToken);

        // Отправляем пользователю токены доступа
        if (refreshRegResult == restbed::CREATED)
        {
            nlohmann::json body;
            body["access_token"] = jwtToken;

            printInfo("INFO authorizationHandler: Successful registration of access tokens.", toScreen);
            session->close(restbed::CREATED, body.dump(),
                {
                    {HeaderConstants::CONTENT_LENGTH, std::to_string(body.dump().length())},
                    {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON},
                    {HeaderConstants::SET_COOKIE, refreshToken}
                }
            );
        }
        else
        {
            // Не удалось зарегистрировать refresh-токен в таблице сессий
            printInfo("INFO authorizationHandler: Registration of access tokens failed. Error code " +
                std::to_string(refreshRegResult), toScreen);
            session->close(refreshRegResult);
        }
    }
    else if (checkResult == restbed::UNAUTHORIZED)
    {
        // Пользователь не зарегистрирован в системе
        printInfo("INFO authorizationHandler: Invalid an email or a password.", toScreen);
        session->close(restbed::UNAUTHORIZED, { { "WWW-Authenticate", "Basic realm=\"" + ServerSettings::REALM + "\""} });
    }
    else
    {
        // Ошибка сервера или что-то другое
        printInfo("INFO authorizationHandler: Failed the authorization. Error code " +
            std::to_string(checkResult), toScreen);
        session->close(checkResult);
    }
}

// Обновляет токены доступа
void refreshTokenHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO refreshTokenHandler RUN.", toScreen);

    // Получаем заголовки
    auto request = session->get_request();
    auto oldJwtToken = request->get_header(HeaderConstants::AUTHORIZATION);
    auto oldRefreshToken = request->get_header(HeaderConstants::COOKIE);

    // Обрезаем префикс заголовка Authorization
    if (!deleteAuthPrefix(oldJwtToken, ServerConstants::BEARER_PREFIX))
    {
        printInfo("INFO refreshTokenHandler: Invalid JWT or Authorization header.", toScreen);
        session->close(restbed::UNAUTHORIZED);

        return;
    }
    
    // Проверка JWT-токена на целостность и получение userEmail пользователя
    AuthToken auth;
    UserData user;
    user.email = auth.checkJwtGetEmail(oldJwtToken);
    if (user.email == ServerConstants::NONE)
    {
        printInfo("INFO refreshTokenHandler: Incorrect JWT or Authorization header.", toScreen);
        session->close(restbed::UNAUTHORIZED);

        return;
    }

    // Трансформируем все символы email в строчные
    strToLowercase(user.email);
    
    // Если токены не сопряжены
    if (!auth.checkJwtRefresh(oldJwtToken, oldRefreshToken))
    {
        printInfo("INFO refreshTokenHandler: Tokens are not paired.", toScreen);
        session->close(restbed::UNAUTHORIZED);

        return;
    }
    
    // Если Refresh-токен просрочен
    if (!auth.checkRefreshExp(oldRefreshToken))
    {
        printInfo("INFO refreshTokenHandler: The refresh token is expired.", toScreen);
        session->close(restbed::UNAUTHORIZED);

        return;
    }

    // Получение данных о пользователе по userEmail
    DbMySQL mySql(g_sqlSettings);
    int resultGetUserData = mySql.getUserDataOnEmail(user);
    if (resultGetUserData != restbed::OK)
    {
        printInfo("ERROR refreshTokenHandler: Getting the user data failed. Error code " + 
            std::to_string(resultGetUserData), toScreen);
        session->close(resultGetUserData);

        return;
    }

    // Создаем новые токены доступа
    const std::string newJwtToken = auth.createJwt(user);
    const std::string newRefreshToken = auth.createRefresh(newJwtToken);

    // Проверка успешности создания токенов
    if (newJwtToken == ServerConstants::NONE || newRefreshToken == ServerConstants::NONE)
    {
        printInfo("ERROR refreshTokenHandler: Creating access tokens failed.", toScreen);
        session->close(restbed::SERVICE_UNAVAILABLE);

        return;
    }

    // Регистрируем refresh-токен в таблице сессий
    int refreshRegResult = mySql.refreshTokens(user.email, newRefreshToken, oldRefreshToken);

    if (refreshRegResult == restbed::CREATED)
    {
        nlohmann::json body;
        body["access_token"] = newJwtToken;

        printInfo("INFO refreshTokenHandler: Successful registration of access tokens.", toScreen);
        session->close(restbed::CREATED, body.dump(),
            {
                {HeaderConstants::CONTENT_LENGTH, std::to_string(body.dump().length())},
                {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON},
                {"Set-Cookie", newRefreshToken}
            }
        );
    }
    else if (refreshRegResult == restbed::UNAUTHORIZED)
    {
        // Пользователь не авторизован
        printInfo("INFO refreshTokenHandler: The user unauthorized.", toScreen);
        session->close(restbed::UNAUTHORIZED, { { "WWW-Authenticate", "Basic realm=\"" + ServerSettings::REALM + "\""} });
    }
    else
    {
        // Что-то пошло не так
        printInfo("ERROR refreshTokenHandler: Tokens refresh failed. Error code " + std::to_string(refreshRegResult), toScreen);
        session->close(refreshRegResult);
    }
}

// Проверяет JWT-токены авторизованных пользователей
void authHandler(const std::shared_ptr<restbed::Session> session, const std::function<void(const std::shared_ptr<restbed::Session>)>& callback)
{
    ScreenLog toScreen;
    printInfo("INFO: authHandler RUN", toScreen);

    // Получаем JWT
    auto jwtToken = session->get_request()->get_header(HeaderConstants::AUTHORIZATION);

    // Обрезаем префикс заголовка Authorization
    if (!deleteAuthPrefix(jwtToken, ServerConstants::BEARER_PREFIX))
    {
        printInfo("INFO authHandler: Invalid JWT or Authorization header.", toScreen);
        session->close(restbed::UNAUTHORIZED);

        return;
    }

    // Проверяем JWT-токен на корректность и просроченность
    AuthToken auth;
    if (auth.checkJwtCheckExp(jwtToken))
    {
        printInfo("INFO authHandler: Callback function RUN.", toScreen);
        callback(session);
    }
    else
    {
        // JWT-токен неверный или просроченный
        printInfo("INFO authHandler: The user unauthorized.", toScreen);
        session->close(restbed::UNAUTHORIZED, { { "WWW-Authenticate", "Basic realm=\"" + ServerSettings::REALM + "\""} });
    }
}

// Возвращает актуальную информацию об авторизованном пользователе
void profileHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO profileHandler RUN.", toScreen);

    auto jwtToken = session->get_request()->get_header(HeaderConstants::AUTHORIZATION);

    // Обрезаем префикс заголовка Authorization
    if (!deleteAuthPrefix(jwtToken, ServerConstants::BEARER_PREFIX))
    {
        printInfo("INFO profileHandler: The user unauthorized.", toScreen);
        session->close(restbed::UNAUTHORIZED);

        return;
    }

    // Получаем email из JWT
    AuthToken auth;
    UserData user;
    user.email = auth.getJwtEmail(jwtToken);
    strToLowercase(user.email);

    // Запрашиваем информацию о пользователе
    DbMySQL mySql(g_sqlSettings);
    int result = mySql.getUserDataOnEmail(user);
    if (result == restbed::OK)
    {
        std::string bodyResponse = getJsonUserDataInStr(user);

        printInfo("INFO profileHandler: Successful operation.", toScreen);
        session->close(restbed::OK, bodyResponse, 
            { 
                {HeaderConstants::CONTENT_LENGTH, std::to_string(bodyResponse.length())}, 
                {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON} 
            }
        );
    }
    else
    {
        // Запрос не был исполнен
        printInfo("ERROR profileHandler: Unsuccessful operation. Error code " + std::to_string(result), toScreen);
        session->close(result);
    }
}

// Изменяет уровень доступа указанного пользователя (срабатывает только для администраторов)
void setAccessHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO setAccessHandler RUN.", toScreen);

    // Получаем заголовки запроса
    const auto request = session->get_request();
    auto jwtToken = request->get_header(HeaderConstants::AUTHORIZATION);

    // Обрезаем префикс заголовка Authorization
    if (!deleteAuthPrefix(jwtToken, ServerConstants::BEARER_PREFIX))
    {
        printInfo("INFO setAccessHandler: The user unauthorized.", toScreen);
        session->close(restbed::UNAUTHORIZED);

        return;
    }

    // Проверка администраторских прав
    AuthToken auth;
    int adminAccess = auth.getJwtAccess(jwtToken);
    if (adminAccess != AccessLayer::ADMIN)
    {
        // Недостаточно прав
        printInfo("INFO setAccessHandler: Not the level of the administrator.", toScreen);
        session->close(restbed::FORBIDDEN);

        return;
    }

    // Получим тело запроса
    size_t contentLength = request->get_header(HeaderConstants::CONTENT_LENGTH, 0);
    session->fetch(contentLength, [request](const std::shared_ptr<restbed::Session> session, const restbed::Bytes& body) 
        {
            ScreenLog toScreen;
            nlohmann::json parsed;
            std::multimap<std::string, std::string> userParams;

            // Распарсим json
            try
            {
                parsed = nlohmann::json::parse(body.data(), body.data() + body.size());
                
                int accessLayer = parsed.at(ServerConstants::ACCESS_LAYER);
                
                std::string userEmail = parsed.at(ServerConstants::EMAIL);
                // Трансформируем все символы email в строчные
                strToLowercase(userEmail);

                userParams.insert(
                    { 
                        {ServerConstants::EMAIL, userEmail},
                        {ServerConstants::ACCESS_LAYER, std::to_string(accessLayer)}
                    }
                );
            }
            catch (const std::exception& exp)
            {
                printInfo("ERROR setAccessHandler. Standart exception: " + std::string(exp.what()), toScreen);
            }

            // Проверка достаточности предоставленных параметров
            if (userParams.count(ServerConstants::EMAIL) != 1 || userParams.count(ServerConstants::ACCESS_LAYER) != 1)
            {
                printInfo("INFO setAccessHandler: Invalid parameters.", toScreen);
                session->close(restbed::BAD_REQUEST);

                return;
            }

            UserData user;
            user.email = userParams.find(ServerConstants::EMAIL)->second;
            std::stringstream ss;
            ss << userParams.find(ServerConstants::ACCESS_LAYER)->second;
            ss >> user.access;

            // Проверка корректности нового уровня доступа
            if (user.access < AccessLayer::MIN_LAYER || user.access > AccessLayer::MAX_LAYER)
            {
                printInfo("INFO setAccessHandler: Invalid the access layer.", toScreen);
                session->close(restbed::BAD_REQUEST);

                return;
            }

            // Меняем уровень пользователя
            DbMySQL mySql(g_sqlSettings);
            int changeResult = mySql.changeAccess(user);
            if (changeResult != restbed::OK)
            {
                // Уровень доступа не изменён
                printInfo("ERROR setAccessHandler: Access level change failed. Error code: " + std::to_string(changeResult), toScreen);
                session->close(changeResult);

                return;
            }

            // Получаем актуальные данные об управляемом пользователе
            int getDataResult = mySql.getUserDataOnEmail(user);
            if (getDataResult == restbed::OK)
            {
                // Возвращаем обновлённые данные о пользователе
                std::string bodyResponse = getJsonUserDataInStr(user);
                printInfo("INFO setAccessHandler: Successful change of access level.", toScreen);
                session->close(restbed::OK, bodyResponse,
                    {
                        {HeaderConstants::CONTENT_LENGTH,
                        std::to_string(bodyResponse.length())},
                        {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON}
                    }
                );
            }
            else
            {
                // Если не удалось получить данные о пользователе (но уровень доступа был изменён)
                printInfo("INFO setAccessHandler: Successful change of access level. But user data could not be retrieved.", toScreen);
                session->close(restbed::NO_CONTENT);  // 204
            }
        }
    );
}

// Возвращает список всех зарегистрированных в системе организаций
void organizationsHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO organizationsHandler RUN.", toScreen);

    // Массив с организациями
    std::vector<Organization> organizations;

    // Запрашиваем список организаций
    DbMySQL mySql(g_sqlSettings);
    int result = mySql.getOrganizations(organizations);
    if (result != restbed::OK)
    {
        printInfo("ERROR organizationsHandler: Could not get a list of organizations.", toScreen);
        session->close(result);

        return;
    }

    // Список организаций пустой
    if (organizations.empty())
    {
        printInfo("INFO organizationsHandler: There are no organizations in the DB.", toScreen);
        session->close(restbed::NO_CONTENT);

        return;
    }

    // Формируем ответ пользователю
    nlohmann::json response;
    int index = 1;
    for (const auto el : organizations)
    {
        nlohmann::json org;
        org[ServerConstants::ORG_ID] = el.id;
        org[ServerConstants::NAME] = el.name;
        response[std::to_string(index++)] = org;
    }

    printInfo("INFO organizationsHandler: The list of organizations has been successfully received.", toScreen);
    session->close(restbed::OK, response.dump(), 
        { 
            {HeaderConstants::CONTENT_LENGTH, std::to_string(response.dump().length())}, 
            {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON} 
        }
    );
}

// Кодирует полученную строку и возвращает файл с QR-кодом
void encodeHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO encodeHandler RUN.", toScreen);

    // Распарсим тело запроса
    const auto request = session->get_request();
    size_t contentLength = request->get_header(HeaderConstants::CONTENT_LENGTH, 0);
    session->fetch(contentLength, [request](const std::shared_ptr<restbed::Session> session, const restbed::Bytes& body)
        {
            ScreenLog toScreen;
            // Содержимое тела запроса
            std::string bodyContent(body.data(), body.data() + int(body.size()));

            // Кодируем строку
            AuthToken auth;
            std::string encoded = auth.base64UrlEncode(bodyContent);
            if (encoded == ServerConstants::NONE)
            {
                printInfo("INFO encodeHandler: Incorrect body request.", toScreen);
                session->close(restbed::INTERNAL_SERVER_ERROR);

                return;
            }

			// Строка для сохранения в QR коде
			std::string qrCodeStr = ServerSettings::PREFIX_QR_CODE + encoded;
            printInfo("INFO encodeHandler. Encoded string: " + qrCodeStr, toScreen);

			// Формируем png файл
			QRcreater qrCode;
			std::string pngResponse = qrCode.createQRcodePNG(qrCodeStr, ServerSettings::PREFIX_QR_FILE);
            if (pngResponse == ServerConstants::NONE)
            {
                // Если не удалось создать png файл
                printInfo("ERROR encodeHandler: Failed to create PNG-file.", toScreen);
                session->close(restbed::INTERNAL_SERVER_ERROR);

                return;
            }

            // Отправляем png файл с QR-кодом пользователю
            printInfo("INFO encodeHandler: Successful PNG-file creation.", toScreen);
            session->close(restbed::CREATED, pngResponse, { 
                {HeaderConstants::CONTENT_LENGTH, std::to_string(pngResponse.length())},
                {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_IMG_PNG} }
            );
        }
    );
}

// Декодирует строку и возвращает json с данными из неё
void decodeHandler(const std::shared_ptr<restbed::Session> session)
{
    ScreenLog toScreen;
    printInfo("INFO decodeHandler RUN.", toScreen);
    
    // Распарсим тело запроса
    auto request = session->get_request();
    size_t contentLength = request->get_header(HeaderConstants::CONTENT_LENGTH, 0);
    session->fetch(contentLength, [request](const std::shared_ptr<restbed::Session> session, const restbed::Bytes& body) 
        {
            ScreenLog toScreen;
            std::string bodyContent(body.data(), body.data() + int(body.size()));
            
            // Проверяем строку на соответствие
            size_t position = bodyContent.find(ServerSettings::PREFIX_QR_CODE);
            if (position == std::string::npos || position != 0)
            {
                printInfo("INFO decodeHandler: Invalid body.", toScreen);
                session->close(restbed::BAD_REQUEST);

                return;
            }

            // Оставляем только содержательную часть
            bodyContent = bodyContent.erase(0, ServerSettings::PREFIX_QR_CODE.length());

            // Декодируем строку
            AuthToken auth;
            std::string decoded = auth.base64UrlDecode(bodyContent);
            if (decoded == ServerConstants::NONE)
            {
                printInfo("INFO decodeHandler: Incorrect content of body.", toScreen);
                session->close(restbed::BAD_REQUEST);

                return;
            }

            // Распарсим информацию из кодированной строки
            std::string delimiter = "%";
            position = 0;
            int iter = 0;
            std::vector <std::string> decodedContent;
            while ((position = decoded.find(delimiter)) != std::string::npos && iter < ServerSettings::ENCODED_STR_SIZE)
            {
                decodedContent.push_back(decoded.substr(0, position));
                decoded.erase(0, position + delimiter.length());
                
                ++iter; // для выхода из цикла, если строка содержит излишне много элементов
            }
            // Остаток строки без '%'
            if (decoded.size())
            {
                decodedContent.push_back(decoded);
            }

            // Строка должна содержать 5 элементов
            if (decodedContent.size() != ServerSettings::ENCODED_STR_SIZE)
            {
                printInfo("INFO decodeHandler: Incorrect encoded content.", toScreen);
                session->close(restbed::BAD_REQUEST);

                return;
            }

            // Формируем json для ответа пользователю
            nlohmann::json jsonBody;
            try
            {
                jsonBody[ServerConstants::NAME] = decodedContent[0];
                
                std::vector<std::string> jsonName{ "project_id", "document_id", "price", "org_id" };
                int index = 1;
                while (index < 5)
                {
                    jsonBody[jsonName[index - 1]] = decodedContent[index];  // цикл начинается со второго элемента - index=1

                    ++index;
                }

                printInfo("INFO decodeHandler: The body content has been successfully decoded.", toScreen);
                session->close(restbed::OK, jsonBody.dump(), {
                    {HeaderConstants::CONTENT_LENGTH, std::to_string(jsonBody.dump().length())},
                    {HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON} }
                );
            }
            catch (const std::exception& exp)
            {
                printInfo("ERROR decodeHandler. Standart exception: " + std::string(exp.what()), toScreen);

                session->close(restbed::BAD_REQUEST);
            }
        }
    );
}


int main()
{
    ScreenLog toScreen;
    printInfo("INFO main(): The REST API Server START!", toScreen);

    // Получаем настройки для БД
    if (!getSqlSettings(ServerSettings::FILE_SQL_SETTINGS))
    {
        printInfo("CRITICAL ERROR main(): There is no SQL settings file. Exit.", toScreen);
        std::cin.get();

        return EXIT_FAILURE;
    }

    // Проверяем подключение к БД
	DbMySQL* mySql = new DbMySQL(g_sqlSettings);
	if (!mySql->checkConnect())
	{
		printInfo("INFO main(): Failed initialization of MySQL.", toScreen);
        delete mySql;
        std::cin.get();  // задержка закрытия

		return EXIT_FAILURE;
	}
    delete mySql;
    
    printInfo("INFO main(): Successful initialization of MySQL.", toScreen);


    // Настройки сервера
    int port = ServerSettings::PORT;
    unsigned int maxThread = ServerSettings::THREAD_NUM;
    printInfo("INFO main(): Number of threads = " + std::to_string(maxThread), toScreen);

    
    // Эндпоинты сервера
    //
    // Регистрация пользователей
    auto registration = std::make_shared<restbed::Resource>();
    registration->set_path(ServerSettings::API_REGISTER);
    registration->set_failed_filter_validation_handler(registrationFailedHandler);
    registration->set_method_handler("POST", 
        { 
            { HeaderConstants::ACCEPT, HeaderConstants::TYPE_APP_JSON }, 
            { HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_APP_JSON } 
        }, &registrationJsonHandler);
    registration->set_method_handler("POST", 
        { 
            { HeaderConstants::ACCEPT, HeaderConstants::TYPE_APP_JSON }, 
            {HeaderConstants::CONTENT_TYPE, "application/x-www-form-urlencoded"} 
        }, &registrationQueryHandler);
    
    // Авторизация пользователей
    auto authorization = std::make_shared<restbed::Resource>();
    authorization->set_path(ServerSettings::API_LOGIN);
    authorization->set_method_handler("GET", authorizationHandler);
    
    // Обновления токенов доступа (JWT + Refresh-token)
    auto refreshToken = std::make_shared<restbed::Resource>();
    refreshToken->set_path(ServerSettings::API_REFRESH_TOKEN);
    refreshToken->set_method_handler("POST", refreshTokenHandler);
    
    // Получение актуальных данных профиля пользователем
    auto profile = std::make_shared<restbed::Resource>();
    profile->set_path(ServerSettings::API_PROFILE);
    profile->set_method_handler("GET", profileHandler);
    profile->set_authentication_handler(authHandler);
    
    // Изменение уровня пользователя администратором
    auto setAccess = std::make_shared<restbed::Resource>();
    setAccess->set_path(ServerSettings::API_ACCESS);
    setAccess->set_method_handler("PATCH", setAccessHandler);
    setAccess->set_authentication_handler(authHandler);
    
    // Получение списка всех организаций
    auto getOrganizations = std::make_shared<restbed::Resource>();
    getOrganizations->set_path(ServerSettings::API_ORGANIZATIONS);
    getOrganizations->set_method_handler("GET", organizationsHandler);
    getOrganizations->set_authentication_handler(authHandler);
    
    // Кодирование строки и получение файла с QR-кодом
    auto encode = std::make_shared<restbed::Resource>();
    encode->set_path(ServerSettings::API_ENCODE);
    encode->set_method_handler("POST", 
        { 
            { HeaderConstants::ACCEPT, HeaderConstants::TYPE_IMG_PNG }, 
            { HeaderConstants::CONTENT_TYPE, HeaderConstants::TYPE_TXT_PLAIN } 
        }, encodeHandler);
    encode->set_authentication_handler(authHandler);
    
    // Декодирование строки
    auto decode = std::make_shared<restbed::Resource>();
    decode->set_path(ServerSettings::API_DECODE);
    decode->set_method_handler("POST", decodeHandler);
    decode->set_authentication_handler(authHandler);


    // Установка настроек сервера
    auto settings = std::make_shared<restbed::Settings>();
    settings->set_port(port);
    settings->set_worker_limit(maxThread);
    settings->set_default_header("Connection", "close");


    // Инициализация сервисов
    restbed::Service service;
    service.publish(registration);
    service.publish(authorization);
    service.publish(refreshToken);
    service.publish(profile);
    service.publish(setAccess);
    service.publish(getOrganizations);
    service.publish(encode);
    service.publish(decode);


    // Запуск сервера
    service.start(settings);

    std::cin.get();

    return EXIT_SUCCESS;
}
