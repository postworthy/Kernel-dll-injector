#include "pch.h"
#include "Log.h"

Log::Log(String* Path) 
{
    logFile.open(Path->c_str(), std::ios_base::app);
}

Log::~Log()
{
    logFile.close();
}

void Log::Write(String* msg)
{
    Write(msg, TRUE);
}
void Log::Write(String* msg, BOOL flush)
{
    logFile << *msg;
    if(flush == TRUE) 
        logFile.flush();
}

void Log::Flush()
{
    logFile.flush();
}