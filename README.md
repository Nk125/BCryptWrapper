# BCryptWrapper
C++ Class to wrap cipher operations in bcrypt dll for windows

No pre-requisites, only C++ stdlib and windows

Example of usage:
```cpp
nk125::BCryptWC bcrypt;
bcrypt.init(bcrypt.AES128);

/*
  You can't use exportKey(),
  but now the key is only stored by internal bcrypt memory and not by the process
*/
bcrypt.preventKeyStorage();

// Generates an AES 128 bits (16 bytes/chars) key.
// To simplify the class it uses ECB, so IV, tag, etc. isn't required, only the key
bcrypt.genKey();

std::string content("Hai i'm plaintext :D");
nk125::bytes con;

// Copies content from string to unsigned char vector
std::copy(content.begin(), content.end(), std::back_inserter(con));

// Encrypts the content in-place
// Actually the cipher text can be anything, as the password is generated randomly
bcrypt.encrypt(con, true);

// Decrypts the ciphered content and returns the plain text, not in-place
con = bcrypt.decrypt(con, false);

// Prints out in the console the plain text
// Hai i'm plaintext :D
std::copy(con.begin(), con.end(), std::ostream_iterator<unsigned char>(std::cout, ""));
```
