#include <stdio.h>
#include <stdlib.h>

#include "digest_thread.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "cryptoki_api.h"

DigestThread::DigestThread()
{

}

DigestThread::~DigestThread()
{

}

void DigestThread::run()
{
//    manApplet->log( "Log Test" );
    CryptokiAPI *pApi = manApplet->cryptokiAPI();

    pApi->Finalize( NULL );
}
