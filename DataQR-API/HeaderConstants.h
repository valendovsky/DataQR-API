#ifndef HEADERCONSTANTS_H
#define HEADERCONSTANTS_H

#include <string>


//  онстанты дл€ формировани€ HTTP заголовков
namespace HeaderConstants
{
	const std::string ACCEPT         = "Accept";
	const std::string AUTHORIZATION  = "Authorization";
	const std::string CONTENT_LENGTH = "Content-Length";
	const std::string CONTENT_TYPE   = "Content-Type";
	const std::string SET_COOKIE     = "Set-Cookie";
	const std::string COOKIE         = "Cookie";
	const std::string TYPE_APP_JSON  = "application/json";
	const std::string TYPE_IMG_PNG   = "image/png";
	const std::string TYPE_TXT_PLAIN = "text/plain";

}

#endif // !HEADERCONSTANTS_H
