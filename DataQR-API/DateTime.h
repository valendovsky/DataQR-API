#ifndef DATETIME_H
#define DATETIME_H

#include <ctime>
#include <string>


// Класс для работы с временем и датой
class DateTime
{
public:
	time_t getTimeNow();
	time_t getExpTimeMin(int minutes, time_t iatTime);
	time_t getRefreshTimeHour(int hours);
	std::string getLocalDateTime();
};

#endif // !DATETIME_H
