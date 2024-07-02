#include "encrypt_thread.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"

#include <QFileInfo>

EncryptThread::EncryptThread()
{

}

EncryptThread::~EncryptThread()
{

}

void EncryptThread::setSession( long uSession )
{
    session_ = uSession;
}

void EncryptThread::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

void EncryptThread::setDstFile( const QString strDstFile )
{
    dst_file_ = strDstFile;
}

void EncryptThread::run()
{
    int rv = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;

    BIN binPart = {0,0};
    BIN binDst = {0,0};

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
        unsigned char *pDecPart = NULL;
        long uDecPartLen = 0;

        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 ) break;

        uDecPartLen = binPart.nLen + 64;

        pDecPart = (unsigned char *)JS_malloc( binPart.nLen + 64 );
        if( pDecPart == NULL ) return;

        rv = manApplet->cryptokiAPI()->EncryptUpdate( session_, binPart.pVal, binPart.nLen, pDecPart, (CK_ULONG_PTR)&uDecPartLen, false );

        if( rv != CKR_OK )
        {
            if( pDecPart ) JS_free( pDecPart );
            fprintf( stderr, "DecryptUpdate execution failure [%s:%d]", JS_PKCS11_GetErrorMsg(rv), rv );
            goto end;
        }

        if( uDecPartLen > 0 )
        {
            JS_BIN_set( &binDst, pDecPart, uDecPartLen );
            JS_free( pDecPart );
            pDecPart = NULL;
            uDecPartLen = 0;
        }

        if( binDst.nLen > 0 )
            JS_BIN_fileAppend( &binDst, dst_file_.toLocal8Bit().toStdString().c_str() );

        nReadSize += nRead;;
        emit taskUpdate( nReadSize );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        JS_BIN_reset( &binDst );
    }

    fclose( fp );

end :
    if( nReadSize == fileSize )
    {
        emit taskFinished();
    }

    JS_BIN_reset( &binPart );
    JS_BIN_reset( &binDst );
}
