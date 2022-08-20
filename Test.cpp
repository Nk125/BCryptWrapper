#include <algorithm>
#include "BCryptWrap.hpp"
#include <iostream>
#include <string>
#include <windows.h>

std::ostream& operator<<(std::ostream& o, nk125::bytes& bs) {
	std::copy(bs.begin(), bs.end(), std::ostream_iterator<unsigned char>(o));
	return o;
}

void asHex(nk125::bytes& bs) {
	int flags = std::cout.flags();
	std::cout << std::hex;

	std::copy(bs.begin(), bs.end(), std::ostream_iterator<unsigned int>(std::cout));

	std::cout.setf(flags);

	return;
}

void encdecTest(nk125::BCryptWC& bc, nk125::bytes& bufa, nk125::bytes& bufb) {
	bufb = bufa;

	std::cout << " = Plain Text: ";
	asHex(bufb);
	std::cout << " =\n\n";

	std::cout << "Encrypting...\n";

	bc.encrypt(bufb, true);

	std::cout << " = Cipher Text: ";
	asHex(bufb);
	std::cout << " =\n\n";

	std::cout << "Decrypting...\n";

	bc.decrypt(bufb, true);
	std::cout << " = Recovered : ";
	asHex(bufb);
	std::cout << " =\n";

	std::cout << "Encryption/Decryption routine " << (bufb == bufa ? "passed succesfully" : "failed") << "\n";
}

int main() {
	nk125::BCryptWC bcEnc;

	try {
		bcEnc.init(bcEnc.AES128);
		std::cout << "Initialized AES-128\n";

		bcEnc.genKey();

		std::cout << "Generated AES 128 bits password (ECB, no IV)\n";
		
		std::string myPassStr = "hai iamapassword", con = "Plaintext";

		nk125::bytes genPass = bcEnc.exportKey(), myPass(myPassStr.begin(), myPassStr.end()), a(con.begin(), con.end()), b;

		std::cout << "Generated password: ";
		asHex(genPass);
		std::cout << "\n";

		std::cout << "Hardcoded password: " << myPass << "\n";

		bcEnc.preventKeyStorage();

		std::cout << "exportKey() returns empty after preventKeyStorage()?: " << (bcEnc.exportKey().empty() ? "true" : "false") << "\n";

		std::cout << "Content to encrypt: " << con << " (";
		asHex(a);
		std::cout << ")\n";

		auto testBothKeys = [&]() {
			bcEnc.importKey(genPass);

			std::cout << "\nTesting encryption/decryption with generated key...\n";

			encdecTest(bcEnc, a, b);

			std::cout << "\nImporting hardcoded key...\n";

			bcEnc.importKey(myPass);

			std::cout << "Testing encryption/decryption with hardcoded key...\n";

			encdecTest(bcEnc, a, b);
		};

		testBothKeys();

		std::cout << "\n = Testing with initOSR() function =\n";

		bcEnc.initOSR(nk125::BCryptWC::CipherAlgorithm(BCRYPT_AES_ALGORITHM, 128));

		testBothKeys();

		std::cout << "All tests passed succesfully!\n";
	}
	catch (nk125::BCryptWC::Exception& e) {
		std::cerr << "Error: " << e.what() << "\n";
	}
}