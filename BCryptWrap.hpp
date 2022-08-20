#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <map>
#include <string>
#include <vector>
#pragma comment(lib, "bcrypt")

namespace nk125 {
	typedef std::vector<unsigned char> bytes;

	// BCrypt Wrapper Class
	class BCryptWC {
	public:
		/*
			This structure is very simple
			bitsize is the bits length you want for the password (128 for AES in example)
			Name, this is the internal bcrypt algorithm name, for example BCRYPT_DES_ALGORITHM
		*/
		struct CipherAlgorithm {
			int bitsize;
			std::wstring Name;

			CipherAlgorithm(std::wstring a, int b) {
				bitsize = b;
				Name = a;
			}

			CipherAlgorithm() {
				bitsize = 0;
				Name = L"NULL";
			}
		};

	private:
		BCRYPT_ALG_HANDLE BCAh;
		bytes genBuf;
		int bits = 0;
		bool storeKey = true;

		struct Key {
			BCRYPT_KEY_HANDLE Handle;
			bytes alloc;
		};

		Key kIObj;

		inline bool NT_SUCCESS(NTSTATUS x) {
			return x >= 0;
		}

		bool wcmp(std::wstring a, std::wstring b) {
			return a.find(b) != std::wstring::npos;
		}

		std::map<int, CipherAlgorithm> cipherList{
			{AES128, CipherAlgorithm(BCRYPT_AES_ALGORITHM, 128)},
			{AES192, CipherAlgorithm(BCRYPT_AES_ALGORITHM, 192)},
			{AES256, CipherAlgorithm(BCRYPT_AES_ALGORITHM, 256)},
		};

		void openAlgorithm(std::wstring name, int bitsz) {
			if (BCryptOpenAlgorithmProvider(&BCAh, name.c_str(), NULL, 0) != 0) {
				throw Exception("Failed to open algorithm");
			}
			else {
				bits = bitsz;
			}
		}

	public:
		/*
			Anonymous enum with the default algorithms and their required key bits length
			You can access to this enum with the class object or the static way

			nk125::BCryptWC::AES128
			OR
			myBCryptWC.AES128
		*/
		enum {
			AES128 = 0,
			AES192,
			AES256
		};

		/*
			Global BCryptWC Exception class
		*/
		class Exception {
		private:
			std::string s;

		public:
			Exception(const char* c) {
				s.assign(c);
			}

			Exception(std::string w) {
				s = w;
			}

			Exception() {
				s = "Unknown Error";
			}

			const char* what() noexcept {
				return s.c_str();
			}
		};

		BCryptWC() {
			kIObj.Handle = NULL;
			BCAh = NULL;
		}

		/*
			Encrypts data with previously initialized password

			@param nk125::bytes = Plaintext
			@param bool = in-place Encryption?
			@return bytes = ciphertext, if valid (else returns plaintext)
		*/
		bytes encrypt(bytes& data, bool inPlace = false) {
			ULONG dsz = static_cast<ULONG>(data.size());
			ULONG esz;

			if (!NT_SUCCESS(BCryptEncrypt(kIObj.Handle, &data[0], dsz, NULL, NULL, 0, NULL, 0, &esz, BCRYPT_BLOCK_PADDING))) {
				throw Exception("Failed to get encrypted size");
				return data;
			}

			genBuf.resize(esz);

			PBYTE ptr = &genBuf[0];

			if (inPlace) {
				data.resize(esz);
				ptr = &data[0];
				genBuf.clear();
			}

			if (!NT_SUCCESS(BCryptEncrypt(kIObj.Handle, &data[0], dsz, NULL, NULL, 0, ptr, esz, &dsz, BCRYPT_BLOCK_PADDING))) {
				throw Exception("Failed to encrypt data");
				return data;
			}

			return genBuf;
		}

		/*
			Decrypts data with previously initialized password

			@param nk125::bytes = Ciphertext
			@param bool = in-place Encryption?
			@return bytes = plaintext, if valid (else returns ciphertext)
		*/
		bytes decrypt(bytes& data, bool inPlace = false) {
			ULONG esz = static_cast<ULONG>(data.size());
			ULONG psz;

			if (!NT_SUCCESS(BCryptDecrypt(kIObj.Handle, &data[0], esz, NULL, NULL, 0, NULL, 0, &psz, BCRYPT_BLOCK_PADDING))) {
				throw Exception("Failed to get encrypted size");
				return data;
			}

			genBuf.resize(esz);

			PBYTE ptr = &genBuf[0];

			if (inPlace) {
				data.resize(esz);
				ptr = &data[0];
				genBuf.clear();
			}

			if (!NT_SUCCESS(BCryptDecrypt(kIObj.Handle, &data[0], esz, NULL, NULL, 0, ptr, psz, &psz, BCRYPT_BLOCK_PADDING))) {
				throw Exception("Failed to encrypt data");
				return data;
			}

			(inPlace ? data : genBuf).resize(psz);

			return genBuf;
		}

		/*
			The password is actually storaged by BCrypt, but if you don't want the password inside
			the process memory space, call this

			@param None
			@return None
		*/
		void preventKeyStorage() {
			storeKey = false;
			kIObj.alloc.clear();
		}

		/*
			Exports the password storaged in the process memory space

			@param None
			@return nk125::bytes = unsigned char key
		*/
		bytes exportKey() {
			return kIObj.alloc;
		}

		/*
			Validates and imports password

			@param nk125::bytes = unsigned char key
			@return None
		*/
		void importKey(bytes& key) {
			ULONG sz = static_cast<ULONG>(key.size());

			if (!NT_SUCCESS(BCryptGenerateSymmetricKey(BCAh, &kIObj.Handle, NULL, 0, &key[0], sz, 0))) {
				throw Exception("Failed to generate symmetric key (probably invalid bit/key size)");
				return;
			}

			if (!NT_SUCCESS(BCryptSetProperty(kIObj.Handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) {
				throw Exception("Failed to set Chaining Mode (ECB)");
				return;
			}

			if (storeKey) {
				kIObj.alloc = key;
			}
		}

		/*
			Generates a key complaining the bit size
			Stores the key in an internal bcrypt key handle and optionally in the process memory space

			@param None
			@return None
		*/
		void genKey() {
			if (!bits) bits = 128;

			int byteSz = bits / 8;

			genBuf.resize(byteSz);

			if (!NT_SUCCESS(BCryptGenRandom(NULL, &genBuf[0], byteSz, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
				throw Exception("Failed to generate random bytes");
				return;
			}

			importKey(genBuf);
			genBuf.clear();
		}

		/*
			Only adds an user-provided algorithm in the cipher algorithm list

			==========================================

			To ubicate the cipher algorithm in init(), you need to add the relative index to the last element in
			the anonymous enum (AES256)

			==========================================

			This function is more preferred than initOSR() because you can discern before key import/generation
			if the algorithm is actually supported by bcrypt (when you call init)
			
			==========================================

			Example:
				The algorithm need to support ECB chaining mode to add a key to it

				byteObf.registerNewAlgorithm(BCryptWC::CipherAlgorithm(BCRYPT_3DES_ALGORITHM, 168));
				byteObf.init(AES256 + 1);


				byteObf.registerNewAlgorithm(BCryptWC::CipherAlgorithm(BCRYPT_DES_ALGORITHM, 56));
				byteObf.init(AES256 + 2);
		*/
		//	==========================================
		/*
			Register a new user-provided algorithm

			@param nk125::BCryptWC::CipherAlgorithm = Algorithm to register
			@return None
		*/
		void registerNewAlgorithm(CipherAlgorithm cA) {
			int id = cipherList.rbegin()->first + 1;
			cipherList[id] = cA;
			return;
		}

		/*
			init() but doesn't check if it's in the registered algorithms by OS
			(init Override System Restrictions)

			@param nk125::BCryptWC::CipherAlgorithm = Algorithm to open
			@return None
		*/
		void initOSR(CipherAlgorithm cA) {
			try {
				openAlgorithm(cA.Name, cA.bitsize);
			}
			catch (Exception& e) {
				throw e;
			}
		}

		/*
			Initialize internal bcrypt algorithm handle

			@param int = Type of algorithm, can be one of the default algorithms or a custom one
			@return None
		*/
		void init(int type = 0) {
			if (type < AES128 || type >= cipherList.size()) {
				throw Exception("Invalid Type");
				return;
			}

			bool found = false;
			ULONG cn = 0;
			BCRYPT_ALGORITHM_IDENTIFIER* bai[1024];
			ZeroMemory(bai, sizeof(bai));

			if (NT_SUCCESS(BCryptEnumAlgorithms(BCRYPT_CIPHER_OPERATION, &cn, bai, 0))) {
				std::wstring name = cipherList[type].Name;

				for (DWORD i = 0; i < cn; i++) {
					BCRYPT_ALGORITHM_IDENTIFIER* alg = std::move(bai[i]);

					if (alg == NULL) continue;

					std::wstring algname = alg->pszName;

					BCryptFreeBuffer(alg);

					if (wcmp(algname, name)) {
						found = true;

						try {
							openAlgorithm(algname, cipherList[type].bitsize);
							break;
						}
						catch (Exception& e) {
							throw e;
						}
					}
				}
			}
			else {
				throw Exception("Internal BCrypt Error");
			}

			if (!found) throw Exception("Algorithm not found");

			return;
		}

		~BCryptWC() {
			if (kIObj.Handle) BCryptDestroyKey(kIObj.Handle);
			if (BCAh) BCryptCloseAlgorithmProvider(BCAh, 0);
		}
	};
}