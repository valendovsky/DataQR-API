#include "ScreenLog.h"

#include <string>

#include "IWriteLog.h"


// ������� ���������� � �������, ��������� ���������� �� ��������� class IWriteLog
void ScreenLog::writeLog(const std::string& message)
{
	IWriteLog::writeLog(message);
}

// ���������� ������� ����� � ����, ��������� ���������� �� ��������� class IWriteLog
std::string ScreenLog::dateTimeNow()
{
	return IWriteLog::dateTimeNow();
}
