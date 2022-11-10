#include "ScreenLog.h"

#include <string>

#include "IWriteLog.h"


// Выводит информацию в консоль, использую реализацию по умолчанию class IWriteLog
void ScreenLog::writeLog(const std::string& message)
{
	IWriteLog::writeLog(message);
}

// Возвращает текущее время и дату, использую реализацию по умолчанию class IWriteLog
std::string ScreenLog::dateTimeNow()
{
	return IWriteLog::dateTimeNow();
}
