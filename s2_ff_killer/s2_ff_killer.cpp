#include <iostream>
#include <filesystem>
#include "FastFileCryptor.h"


int main(int argc, char** argv)
{
	std::cout << "| ------------------------------" << std::endl;
	std::cout << "| s2_ff_killer - WW2 FF Decrypter" << std::endl;
	std::cout << "| Developed by Scobalula" << std::endl;
	std::cout << "| ------------------------------" << std::endl;
	std::cout << "| Initializing LibTomCrypt...." << std::endl;
	FastFileCryptor::InitTomCrypt();
	std::cout << "| Initialized LibTomCrypt." << std::endl;

	if (argc < 2)
	{
		std::cout << "| No files provided." << std::endl;
		std::cout << "| To use, drag and drop fast files onto the exe." << std::endl;
	}
	else
	{
		for (int i = 1; i < argc; i++)
		{
			auto fileName = std::filesystem::path(argv[i]).filename().string();
			std::cout << "| Processing: " << fileName << "..." << std::endl;

			try
			{
				FastFileCryptor::Decrypt(argv[i]);
			}
			catch (const std::exception& ex)
			{
				std::cout << "| ERROR: " << ex.what() << "." << std::endl;
				continue;
			}

			std::cout << "| Processed: " << fileName << "." << std::endl;
		}
	}

	std::cout << "| Complete, press enter to exit." << std::endl;
	std::cin.get();
}