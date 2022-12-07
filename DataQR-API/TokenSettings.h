#ifndef TOKENSETTINGS_H
#define TOKENSETTINGS_H

#include <string>


// ��������� ��� ������������ JWT � Refresh token'a
namespace TokenSettings
{
	const std::string JWT_ISS_NAME  = "auth.DataQR-API.com";
	const std::string JWT_ALG_HS256 = "HS256";
	const std::string KEY_JWT       = "1234567890123456";     // ���� ������������ JWT
	const std::string JWT_ALG       = "alg";
	const std::string JWT_TYP       = "typ";
	const std::string JWT_TYP_JWT   = "JWT";
	const std::string JWT_ISS       = "iss";
	const std::string JWT_IAT       = "iat";
	const std::string JWT_EXP       = "exp";

	const int REFRESH_EXP_TIME      = 168;  // 7 ���� � �����
	const int JWT_EXP_TIME          = 15;   // 15 �����
	const int JWT_REFRESH_END       = 6;    // ����� ��������� 6 �������� � JWT � Refresh �������

}

#endif // !TOKENSETTINGS_H
