#include <Windows.h>
#include "Helper.h"

const std::filesystem::path Helper::GetMainModulePath()
{
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);

	// Check if our file path is too small
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		return "";

	return path;
}
