#include "IWriteLog.h"

#include <string>
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>

#include "DateTime.h"


extern std::mutex g_mtxCout;

// Выводит информацию в консоль (реализация по умолчанию)
void IWriteLog::writeLog(const std::string& message)
{
	std::lock_guard<std::mutex> lock(g_mtxCout);
	std::cout << IWriteLog::dateTimeNow() << " [#" << std::this_thread::get_id() << "] >>> " << message << '\n';
}

// Возвращает текущую дату и время (реализация по умолчанию)
std::string IWriteLog::dateTimeNow()
{
	DateTime DateTime;
	std::string localDateTime = DateTime.getLocalDateTime();
	
	std::stringstream ss;
	ss << localDateTime;
	
	std::string month;
	std::string day;
	std::string time;
	std::string year;
	ss >> month >> month >> day >> time >> year;

	std::string timeNow = year + "-" + month + "-" + day + " " + time;

	return timeNow;
}
