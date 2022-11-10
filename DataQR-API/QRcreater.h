#ifndef QRCREATER_H
#define QRCREATER_H

#include <string>

#include <qrencode.h>

#include "IWriteLog.h"


// Класс для работы с QR-кодами
class QRcreater
{
private:
	int m_size = 3;
	int m_margin = 3;
	int m_dpi = 72;
	unsigned int m_fg_color[4] = { 0, 0, 0, 255 };
	unsigned int m_bg_color[4] = { 255, 255, 255, 255 };

	void printInfo(const std::string& message, IWriteLog& typeLog);
	int createPNGfile(QRcode* qrCode, const char* pngFile);

public:
	QRcreater(){}

	std::string createQRcodePNG(const std::string& qrCodeStr, const std::string& prefixPngFile);

};

#endif // !QRCREATER_H
