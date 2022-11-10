#ifndef SCREENLOG_H
#define SCREENLOG_H

#include <string>

#include "IWriteLog.h"


// Класс логирует информацию в консоль
class ScreenLog : public IWriteLog
{
public:
	virtual void writeLog(const std::string& message) override;
	virtual ~ScreenLog() override {}

protected:
	virtual std::string dateTimeNow() override;

};

#endif // !SCREENLOG_H
