#pragma once
#include "tomcrypt.h"
#include <fstream>
#include <string>

namespace FastFileCryptor
{
	/// <summary>
	/// Initializes Tom Crypt
	/// </summary>
	void InitTomCrypt();

	/// <summary>
	/// Decrypts the provided file.
	/// </summary>
	/// <param name="filePath">The path of the file to decrypt.</param>
	void Decrypt(const std::string& filePath);

	/// <summary>
	/// Decrypts the provided file.
	/// </summary>
	/// <param name="filePath">The path of the file to decrypt.</param>
	void Decrypt(const char* filePath);
};

