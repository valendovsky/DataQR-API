#include "DateTime.h"

#include <ctime>
#include <chrono>
#include <string>


// ���������� ����� �������� ������ (iat)
time_t DateTime::getTimeNow()
{
	std::chrono::time_point<std::chrono::system_clock> iatTime = std::chrono::system_clock::now();

	return std::chrono::system_clock::to_time_t(iatTime);
}

// ���������� ����� �������� ����� ����� ������ (exp)
time_t DateTime::getExpTimeMin(int minutes, time_t iatTime)
{
	std::chrono::time_point<std::chrono::system_clock> expTime = std::chrono::system_clock::from_time_t(iatTime) + std::chrono::minutes(minutes);

	return std::chrono::system_clock::to_time_t(expTime);
}

// ���������� ����� ����� Refresh-������
time_t DateTime::getRefreshTimeHour(int hours)
{
	time_t iatTime = getTimeNow();
	std::chrono::minutes min = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::hours(hours));

	return getExpTimeMin(min.count(), iatTime);
}

// ���������� ��������� ���� � �����
std::string DateTime::getLocalDateTime()
{
	time_t seconds = time(0);
	tm* localTime = std::localtime(&seconds);
	std::string time_asc(std::asctime(localTime));

	return time_asc;
}
