#pragma once

class Log
{
private:

#ifdef UNICODE
	std::wofstream logFile;
#else
	std::ofstream logFile;
#endif // UNICODE

public:
	Log(String *path);
	~Log();
	void Write(String* msg);
	void Write(String* msg, BOOL flush);
	void Flush();
};

