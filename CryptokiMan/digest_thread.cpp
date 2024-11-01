#include <stdio.h>
#include <stdlib.h>

#include "digest_thread.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"

#include <QFileInfo>

DigestThread::DigestThread()
{
    session_ = -1;
}

DigestThread::~DigestThread()
{

}

void DigestThread::setSession( long uSession )
{
    session_ = uSession;
}

void DigestThread::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

void DigestThread::run()
{
    int ret = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;

    BIN binPart = {0,0};

    QFileInfo fileInfo;
    fileInfo.setFile( src_file_ );

    qint64 fileSize = fileInfo.size();

    nLeft = fileSize;

    FILE *fp = fopen( src_file_.toLocal8Bit().toStdString().c_str(), "rb" );

    if( fp == NULL )
    {
        fprintf( stderr, "failed to read file:%s\n", src_file_.toStdString().c_str());
        goto end;
    }

    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            fprintf( stderr, "fail to read file: %d\n", nRead );
            goto end;
        }

        ret = manApplet->cryptokiAPI()->DigestUpdate( session_, binPart.pVal, binPart.nLen, false );
        if( ret != CKR_OK )
        {
            fprintf( stderr, "DigestUpdate execution failure [%s:%d]\n", JS_PKCS11_GetErrorMsg(ret), ret);
            goto end;
        }

        nReadSize += nRead;
        emit taskUpdate( nReadSize );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
    }

    fclose( fp );

end :
    if( nReadSize == fileSize )
    {
        emit taskFinished();
    }

    JS_BIN_reset( &binPart );
}
