# DSA

Данное консольное приложение написанное на C++ с использованием библиотеки OpenSSL, реализует процесс подписания файла электронной подписью, после подписания файла создается дополнительные файлы с названиями signature.txt, PublicKey, PrivateKey. signature.txt - является подписью данного файла, PublicKey и PrivateKey - открытый и закрытый ключи.

После того как файл был подписан, можно проверить его целлостность, для этого необоходимо иметь саму подпись, а также открытый ключ. 

 
