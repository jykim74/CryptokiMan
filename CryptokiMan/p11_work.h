#ifndef P11_WORK_H
#define P11_WORK_H

#include "pkcs11.h"
#include "cryptoki_api.h"


int getRSAPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey );
int getECPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey );
int getDSAPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey );
int getEDPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey );

int getPublicKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPubKey );

#endif // P11_WORK_H
