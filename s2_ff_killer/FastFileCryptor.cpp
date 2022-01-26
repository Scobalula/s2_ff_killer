#include <iostream>
#include <fstream>
#include <filesystem>
#include <Windows.h>
#include "FastFileCryptor.h"
#include "Key.h"
#include <iostream>

struct S2FFHeader
{
	uint64_t Magic;
	uint32_t Version;
	uint32_t VersionEx;
	uint32_t Flags;
	uint32_t Unk[3];
};

void FastFileCryptor::InitTomCrypt()
{
	if (register_hash(&sha256_desc) != CRYPT_OK)
	{
		std::cout << "| FATAL: Failed to register SHA256." << std::endl;
		std::cin.get();
		exit(-1);
	}
	if (register_cipher(&aes_desc) != CRYPT_OK)
	{
		std::cout << "| FATAL: Failed to register AES." << std::endl;
		std::cin.get();
		exit(-1);
	}
	if (crypt_mp_init("ltm") != CRYPT_OK)
	{
		std::cout << "| FATAL: Failed to register LTM." << std::endl;
		std::cin.get();
		exit(-1);
	}
}

void FastFileCryptor::Decrypt(const std::string& filePath)
{
	Rsa_key key{};

	int sha_idx = find_hash("sha256");
	int aes_idx = find_cipher("aes");

	std::ifstream input;
	std::ofstream output;

	input.exceptions(std::ios::failbit | std::ios::badbit);
	output.exceptions(std::ios::failbit | std::ios::badbit);

	input.open(filePath, std::ios::binary);

	std::filesystem::path curPath = filePath;
	std::filesystem::path newPath = filePath + ".decrypted.ff";

	S2FFHeader header{};

	input.read((char*)&header, sizeof(header));

	// Note encrypted, but don't throw an error
	// just skip
	if (header.Magic == 0x3030317566663153)
		return;
	// Validate our magic number and version
	// before we continue to ensure we have a 
	// valid WW2 Fast File
	if (header.Magic != 0x3030313066663153)
		throw std::exception("Invalid Fast File Magic.");
	if (header.Version != 0x5)
		throw std::exception("Invalid Fast File Version.");


	uint32_t itemCount = 0;

	// These tables are used for streaming from pak
	// files afaik and so aren't useful to use, therefore
	// we can skip them and dump a dummy value.
	input.read((char*)&itemCount, sizeof(itemCount));
	input.seekg((size_t)itemCount * 16, std::ios::cur);
	input.read((char*)&itemCount, sizeof(itemCount));
	input.seekg((size_t)itemCount * 16, std::ios::cur);

	uint32_t dummy = 0;
	uint64_t dataSizes[12]{};

	input.read((char*)&dataSizes, sizeof(dataSizes));

	std::filesystem::create_directories(newPath.parent_path());

	output.open(newPath, std::ios::binary);

	// Dump the header back
	output.write((const char*)&header, sizeof(header));
	output.write((const char*)&dummy, sizeof(dummy));
	output.write((const char*)&dummy, sizeof(dummy));
	output.write((const char*)&dataSizes, sizeof(dataSizes));

	// We need buffers for our key, initial block
	// and our master and key blocks
	// The key block will contain keys for our active blocks
	auto initialKey      = std::make_unique<uint8_t[]>(40);
	auto initialBlock    = std::make_unique<uint8_t[]>(256);
	auto masterBlock     = std::make_unique<uint8_t[]>(16384);
	auto currentBlock    = std::make_unique<uint8_t[]>(16384);
	auto currentKeyBlock = std::make_unique<uint8_t[]>(16384);

	int state = 0;

	input.read((char*)initialBlock.get(), 256);
	input.read((char*)masterBlock.get(), 16384);

	// Start with the master block, it's required for keys for
	// all the other blocks in the file
	unsigned long keySize = 40;
	int stat = 0;

	rsa_import(RSAKey, sizeof(RSAKey), &key);
	rsa_decrypt_key(initialBlock.get(), 256, initialKey.get(), &keySize, nullptr, 0, sha_idx, &stat, &key);
	rsa_free(&key);


	symmetric_CTR c{};
	
	if (ctr_start(aes_idx, initialKey.get() + 24, initialKey.get(), 24, 0, 0, &c) != CRYPT_OK)
		throw std::exception("Failed to start CTR encryption.");
	if (ctr_decrypt(masterBlock.get(), masterBlock.get(), 16384, &c) != CRYPT_OK)
		throw std::exception("Failed to decrypt initial block.");

	size_t remaining = dataSizes[0] - (size_t)input.tellg();

	size_t hashblockIndex = 0;
	size_t datablockIndex = 0;

	// Keep consuming and decrypting while
	// we have data.
	while (remaining > 0)
	{
		size_t blockSize = min(16384, remaining);

		input.read((char*)currentBlock.get(), 16384);

		// Check our state to see if we are processing
		// a normal data block, or a key block, and update
		// accordingly
		if (state == 0)
		{
			ctr_setiv(masterBlock.get() + 336 + hashblockIndex++ * 32, 16, &c);

			if (ctr_decrypt(currentBlock.get(), currentKeyBlock.get(), 16384, &c) != CRYPT_OK)
				throw std::exception("Failed to decrypt key block.");

			datablockIndex = 0;
			state = 1;
		}
		else
		{
			ctr_setiv(currentKeyBlock.get() + datablockIndex++ * 32, 16, &c);

			if (ctr_decrypt(currentBlock.get(), currentBlock.get(), 16384, &c) != CRYPT_OK)
				throw std::exception("Failed to decrypt data block.");

			output.write((const char*)currentBlock.get(), 16384);

			// Check if we need to request the next hash block
			if (datablockIndex == 512)
				state = 0;
		}

		remaining -= blockSize;
	}
}

void FastFileCryptor::Decrypt(const char* filePath)
{
	std::string filePathStr = filePath;
	Decrypt(filePathStr);
}