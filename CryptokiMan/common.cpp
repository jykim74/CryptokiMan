#include <QFileDialog>
#include <QDate>

#include "common.h"


QString findFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

//    QString strPath = QDir::currentPath();

    QString strType;
    QString selectedFilter;

    if( nType == JS_FILE_TYPE_CERT )
        strType = QObject::tr("Cert Files (*.crt *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_PRIKEY )
        strType = QObject::tr("Key Files (*.key *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_TXT )
        strType = QObject::tr("TXT Files (*.txt *.log);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BER )
        strType = QObject::tr("BER Files (*.ber *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_DLL )
        strType = QObject::tr( "DLL Files (*.dll);;SO Files (*.so);;All Files (*.*)" );
    else if( nType == JS_FILE_TYPE_PFX )
        strType = QObject::tr("PFX Files (*.pfx *.p12 *.pem);;All Files(*.*)");

    QString fileName = QFileDialog::getOpenFileName( parent,
                                                     QObject::tr( "Open File" ),
                                                     strCurPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    return fileName;
};

void getCKDate( const QDate date, CK_DATE *pCKDate )
{
    if( pCKDate == NULL ) return;

    char    sYear[5];
    char    sMonth[3];
    char    sDay[3];

    memset( sYear, 0x00, sizeof(sYear));
    memset( sMonth, 0x00, sizeof(sMonth));
    memset( sDay, 0x00, sizeof(sDay));

    sprintf( sYear, "%04d", date.year() );
    sprintf( sMonth, "%02d", date.month() );
    sprintf( sDay, "%02d", date.day() );

    memcpy( pCKDate->year, sYear, 4 );
    memcpy( pCKDate->month, sMonth, 2 );
    memcpy( pCKDate->day, sDay, 2 );
}

QString getBool( const BIN *pBin )
{
    QString strOut = "";
    if( pBin == NULL ) return "None";


    if( pBin->nLen == 0 )
        strOut = "None";
    else if( pBin->nLen > 1 )
        strOut = "Invalid";
    else
    {
        if( pBin->pVal[0] == 0x00 )
            strOut = "FALSE";
        else
            strOut = "TRUE";
    }

    return strOut;
}
