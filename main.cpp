#include "DSA.h"

using namespace std;

int main() {
	MyDSA dsa;
	dsa.readFiles();
	if (!dsa.isSigned()) {
		cout << "It is impossible to know if the file is signed because the signature file or the public key has not been specifie" << endl;
		cout << "Do you want to sign the file ? (Y/N) " << endl;
		char ch;
		cin >> ch;
		if (ch == 'Y' || ch == 'y') {
			if (!dsa.creatingDigitalSignature()) {
				cerr << "Failed to sign the file" << endl;
				return 0;
			}
			cout << "The signature has been created and is in the file signature.txt" << endl;
		}
		else {
			return 0;
		}
	}
	else {
		if (dsa.checkFileSignature()) {
			cout << "The file is digitally signed and has not been modified" << endl;
		}
		else {
			cout << "The digital signature of the file has not been confirmed" << endl;
		}
		cout << "------------------------------------------------------" << endl;
		cout << "Do you want to resign the file ? (Y/N) " << endl;
		char ch;
		cin >> ch;
		if (ch == 'Y') {
			if (!dsa.creatingDigitalSignature()) {
				cerr << "Failed to sign the file" << endl;
				return 0;
			}
			cout << "The signature has been created and is in the file signature.txt" << endl;
		}
		else {
			return 0;
		}
	}
}