#include "sign_thread.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"

#include <QFileInfo>

SignThread::SignThread()
{

}

SignThread::~SignThread()
{

}

void SignThread::setSession( long uSession )
{
    session_ = uSession;
}

void SignThread::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

void SignThread::run()
{
    int ret = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    qint64 nReadSize = 0;
    int nLeft = 0;
    qint64 nOffset = 0;

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

        ret = manApplet->cryptokiAPI()->SignUpdate( session_, binPart.pVal, binPart.nLen, false );
        if( ret != CKR_OK )
        {
            fprintf( stderr, "SignUpdate execution failure [%s:%d]\n", JS_PKCS11_GetErrorMsg(ret), ret);
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
