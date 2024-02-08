#pragma warning(disable : 4996)
#include "DSA.h"


#define ERROR_OPEN_FILE 2


MyDSA::MyDSA() {
    is_signed = 1;
}

void MyDSA::readFiles() {
    std::cout << "Enter the file location" << std::endl;
    std::cin >> fileFullPath;
    hash = hashFile(fileFullPath);

    std::cout << "Enter the location of the signed file or 0" << std::endl;
    std::cin >> signatureLocation;
    if (signatureLocation == "0") {
        is_signed = 0;
        return;
    }

    std::cout << "Enter the path to the public key or press enter" << std::endl;
    std::cin >> publickeyLocation;
    if (publickeyLocation == "0") {
        is_signed = 0;
        return;
    }
}

bool MyDSA::isSigned() {
    return is_signed;
}

void MyDSA::readSignature() {
    std::ifstream file(signatureLocation);
    if (!file) {
        throw std::runtime_error("The file could not be opened: " + signatureLocation);
    }

    std::getline(file, signature, '\0');
    file.close();
}

RSA* MyDSA::readPublicKey(const std::string& publickey) {
    std::ifstream file(publickey);
    if (!file) {
        throw std::runtime_error("The file could not be opened: " + publickey);
    }

    std::string key;
    std::getline(file, key, '\0');
    file.close();

    RSA* rsa;
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, key.c_str(), key.length());
    EVP_PKEY* pk = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    rsa = EVP_PKEY_get1_RSA(pk);
    BIO_free(bio);
    EVP_PKEY_free(pk);

    return rsa;
}

RSA* MyDSA::readPrivateKey(const std::string& privatekey) {
    std::ifstream file(privatekey);
    if (!file) {
        throw std::runtime_error("The file could not be opened: " + privatekey);
    }

    std::string key;
    std::getline(file, key, '\0');
    file.close();

    RSA* rsa;

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, key.c_str(), key.length());
    EVP_PKEY* pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    rsa = EVP_PKEY_get1_RSA(pk);
    BIO_free(bio);
    EVP_PKEY_free(pk);

    return rsa;
}

std::string MyDSA::hashFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("The file could not be opened: " + filename);
    }

    SHA256_CTX sha;
    SHA256_Init(&sha);

    char buffer[1024];
    while (file.read(buffer, 1024)) {
        SHA256_Update(&sha, buffer, file.gcount());
    }
    std::cout << std::endl;

    file.close();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha);

    std::string output;
    char buffer2[3];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf_s(buffer2, "%02x", hash[i]);
        output += buffer2;
    }

    return output;
}

bool MyDSA::checkFileSignature() {
    readSignature();
    decryptSignature(signature, publickeyLocation, (int)hash.size());

    if (hash == decryptedSignature) {
        return true;
    }
    else {
        return false;
    }
}

RSA* MyDSA::generateKeyPair(int bits, unsigned long exp) {
    RSA* rsa = NULL;
    BIGNUM* bne = NULL;
    int result = 0;

    bne = BN_new();
    result = BN_set_word(bne, exp);
    if (result != 1) {
        std::cerr << "Error setting the BIGNUM value" << std::endl;
        return nullptr;
    }

    rsa = RSA_new();
    result = RSA_generate_key_ex(rsa, bits, bne, NULL);
    if (result != 1)
    {
        std::cerr << "Error generating RSA keys" << std::endl;
        return nullptr;
    }

    BN_free(bne);

    return rsa;
}

bool MyDSA::writePublicKey(RSA* rsa, const std::string& fileName) {
    BIO* bio = NULL;
    int result = 0;

    bio = BIO_new_file(fileName.c_str(), "w+");
    if (bio == NULL)
    {
        std::cerr << "Error creating the BIO object" << std::endl;
        return false;
    }

    result = PEM_write_bio_RSAPublicKey(bio, rsa);
    if (result != 1)
    {
        std::cerr << "Error writing the RSA public key" << std::endl;
        return false;
    }

    BIO_free(bio);

    return true;
}

bool MyDSA::writePrivateKey(RSA* rsa, const std::string& fileName) {
    BIO* bio = NULL;
    int result = 0;

    bio = BIO_new_file(fileName.c_str(), "w+");
    if (bio == NULL)
    {
        std::cerr << "Error creating the BIO object" << std::endl;
        return false;
    }

    result = PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    if (result != 1)
    {
        std::cerr << "Error writing the RSA private key" << std::endl;
        return false;
    }

    BIO_free(bio);

    return true;
}

bool MyDSA::decryptSignature(const std::string& signature, const std::string& publicKeyFile, int hashLen) {
    RSA* rsa = readPublicKey(publicKeyFile);
    if (rsa == nullptr) {
        throw std::runtime_error("The RSA public key could not be read");
    }

    int keyLen = RSA_size(rsa);

    unsigned char* buffer = new unsigned char[keyLen];

    int result = RSA_public_decrypt(signature.length(), (unsigned char*)signature.c_str(), buffer, rsa, RSA_PKCS1_PADDING);

    if (result == -1)
    {
        std::cerr << "Hash decryption error" << std::endl;
        return false;
    }

    decryptedSignature = std::string((char*)buffer, hashLen);

    delete[] buffer;
    RSA_free(rsa);

    return true;
}

bool MyDSA::encryptHashPrivate(const std::string& hash, const std::string& privateKeyFile, std::string& signature) {
    RSA* rsa = readPrivateKey(privateKeyFile);
    if (rsa == nullptr) {
        throw std::runtime_error("The RSA private key could not be read");
    }

    int keyLen = RSA_size(rsa);

    unsigned char* buffer = new unsigned char[keyLen];


    int result = RSA_private_encrypt(hash.length(), (unsigned char*)hash.c_str(), buffer, rsa, RSA_PKCS1_PADDING);

    if (result == -1)
    {
        std::cerr << "Hash encryption error" << std::endl;
        return false;
    }

    signature = std::string((char*)buffer, keyLen);

    delete[] buffer;
    RSA_free(rsa);

    return true;
}

bool MyDSA::createFileSignature() {
    std::ofstream file("signature.txt", std::ios_base::out);
    if (file.is_open()) {
        file << signature;
        file.close();
        return true;
    }
    return false;
}

bool MyDSA::creatingDigitalSignature() {
    RSA* rsa = generateKeyPair(1024, RSA_F4);
    if (!writePublicKey(rsa, publickeyName))
        return false;
    if (!writePrivateKey(rsa, privatekeyName))
        return false;
    if (!encryptHashPrivate(hash, privatekeyName, signature))
        return false;
    if (!createFileSignature())
        return false;
    return true;
}


