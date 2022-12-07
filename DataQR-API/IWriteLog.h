#ifndef IWRITELOG_H
#define IWRITELOG_H

#include <string>


// ������������ ����� ��� ���������� �����
class IWriteLog
{
public:
	virtual void writeLog(const std::string& message) = 0;

	virtual ~IWriteLog() {}

protected:
	virtual std::string dateTimeNow() = 0;

};

#endif // !IWRITELOG_H
