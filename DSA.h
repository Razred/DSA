#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

class MyDSA {
public:

    MyDSA();

    void readFiles();

    bool isSigned();

    bool creatingDigitalSignature();

    bool checkFileSignature();

private:
    std::string fileFullPath;
    std::string signatureLocation;
    std::string publickeyLocation;

    bool is_signed;

    std::string hash;
    std::string signature;
    std::string decryptedSignature;
    std::string privatekeyName = "PrivateKey";
    std::string publickeyName = "PublicKey";

    void readSignature();

    RSA* readPublicKey(const std::string& publickey);

    RSA* readPrivateKey(const std::string& privatekey);
   
    std::string hashFile(const std::string& filename);


    RSA* generateKeyPair(int bits, unsigned long exp);

    bool writePublicKey(RSA* rsa, const std::string& fileName);

    bool writePrivateKey(RSA* rsa, const std::string& fileName);

    bool decryptSignature(const std::string& signature, const std::string& publicKeyFile, int hashLen);

    bool encryptHashPrivate(const std::string& hash, const std::string& privateKeyFile, std::string& signature);

    bool createFileSignature();

};