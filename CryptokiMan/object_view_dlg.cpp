#include "object_view_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "common.h"
#include "cryptoki_api.h"

ObjectViewDlg::ObjectViewDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mReloadBtn, SIGNAL(clicked()), this, SLOT(clickReload()));

    connect( mCommonTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickCommonField(QModelIndex)));
    connect( mPart1Table, SIGNAL(clicked(QModelIndex)), this, SLOT(clickPart1Field(QModelIndex)));
    connect( mPart2Table, SIGNAL(clicked(QModelIndex)), this, SLOT(clickPart2Field(QModelIndex)));
    connect( mPart3Table, SIGNAL(clicked(QModelIndex)), this, SLOT(clickPart3Field(QModelIndex)));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ObjectViewDlg::~ObjectViewDlg()
{

}

void ObjectViewDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotNameText->setText( slot_info_.getDesc() );
    }

    mSlotIDText->setText( QString( "%1").arg(slot_info_.getSlotID()));
    mSessionText->setText( QString("%1").arg(slot_info_.getSessionHandle()));
    mLoginText->setText( slot_info_.getLogin() ? "YES" : "NO" );
}

void ObjectViewDlg::initialize()
{

}

void ObjectViewDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };
    QStringList sFieldTypes = { tr("All"), tr("Version1 Only"), tr("Extension Only"), tr("Critical Extension Only"), tr("Attribute Only") };

    mCommonTable->clear();
    mCommonTable->horizontalHeader()->setStretchLastSection(true);
    mCommonTable->setColumnCount(2);
    mCommonTable->setHorizontalHeaderLabels( sBaseLabels );
    mCommonTable->verticalHeader()->setVisible(false);
    mCommonTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCommonTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCommonTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mPart1Table->clear();
    mPart1Table->horizontalHeader()->setStretchLastSection(true);
    mPart1Table->setColumnCount(2);
    mPart1Table->setHorizontalHeaderLabels( sBaseLabels );
    mPart1Table->verticalHeader()->setVisible(false);
    mPart1Table->horizontalHeader()->setStyleSheet( kTableStyle );
    mPart1Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPart1Table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mPart2Table->clear();
    mPart2Table->horizontalHeader()->setStretchLastSection(true);
    mPart2Table->setColumnCount(2);
    mPart2Table->setHorizontalHeaderLabels( sBaseLabels );
    mPart2Table->verticalHeader()->setVisible(false);
    mPart2Table->horizontalHeader()->setStyleSheet( kTableStyle );
    mPart2Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPart2Table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mPart3Table->clear();
    mPart3Table->horizontalHeader()->setStretchLastSection(true);
    mPart3Table->setColumnCount(2);
    mPart3Table->setHorizontalHeaderLabels( sBaseLabels );
    mPart3Table->verticalHeader()->setVisible(false);
    mPart3Table->horizontalHeader()->setStyleSheet( kTableStyle );
    mPart3Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPart3Table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mObjectToolBox->setItemEnabled( 1, false );
    mObjectToolBox->setItemEnabled( 2, false );
    mObjectToolBox->setItemEnabled( 3, false );

    mObjectToolBox->setItemText( 1, tr("NA"));
    mObjectToolBox->setItemText( 2, tr("NA"));
    mObjectToolBox->setItemText( 3, tr("NA"));
}

void ObjectViewDlg::clickReload()
{
    long hObject = mObjectText->text().toLong();

    mCommonTable->setRowCount(0);
    mPart1Table->setRowCount(0);
    mPart2Table->setRowCount(0);
    mPart3Table->setRowCount(0);

    mObjectToolBox->setItemEnabled( 1, false );
    mObjectToolBox->setItemEnabled( 2, false );
    mObjectToolBox->setItemEnabled( 3, false );

    mObjectToolBox->setItemText( 1, tr("NA"));
    mObjectToolBox->setItemText( 2, tr("NA"));
    mObjectToolBox->setItemText( 3, tr("NA"));

    setObject( hObject );
}

void ObjectViewDlg::clickCommonField( QModelIndex index )
{
    int row = index.row();
    QTableWidgetItem *item0 = mCommonTable->item( row, 0 );
    QTableWidgetItem* item1 = mCommonTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    QString strDetail;
    strDetail = "=========================================\n";
    strDetail += QString( "== %1\n" ).arg( item0->text() );
    strDetail += "=========================================\n";
    strDetail += item1->text();

    mDetailText->setPlainText( strDetail );
}

void ObjectViewDlg::clickPart1Field( QModelIndex index )
{
    int row = index.row();
    QTableWidgetItem *item0 = mPart1Table->item( row, 0 );
    QTableWidgetItem* item1 = mPart1Table->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    QString strDetail;
    strDetail = "=========================================\n";
    strDetail += QString( "== %1\n" ).arg( item0->text() );
    strDetail += "=========================================\n";
    strDetail += item1->text();

    mDetailText->setPlainText( strDetail );
}

void ObjectViewDlg::clickPart2Field( QModelIndex index )
{
    int row = index.row();

    QTableWidgetItem *item0 = mPart2Table->item( row, 0 );
    QTableWidgetItem* item1 = mPart2Table->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    QString strDetail;
    strDetail = "=========================================\n";
    strDetail += QString( "== %1\n" ).arg( item0->text() );
    strDetail += "=========================================\n";
    strDetail += item1->text();

    mDetailText->setPlainText( strDetail );
}

void ObjectViewDlg::clickPart3Field( QModelIndex index )
{
    int row = index.row();
    QTableWidgetItem *item0 = mPart3Table->item( row, 0 );
    QTableWidgetItem* item1 = mPart3Table->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    QString strDetail;
    strDetail = "=========================================\n";
    strDetail += QString( "== %1\n" ).arg( item0->text() );
    strDetail += "=========================================\n";
    strDetail += item1->text();

    mDetailText->setPlainText( strDetail );
}

QString ObjectViewDlg::stringAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj, int* pnLen )
{
    int ret = 0;

    char    *pStr = NULL;
    QString strMsg;
    BIN     binVal = {0,0};

    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObj, uAttribute, &binVal );

    if( ret == CKR_OK )
    {
        if( pnLen ) *pnLen = binVal.nLen;

        if( nValType == ATTR_VAL_BOOL )
        {
            strMsg = getBool( &binVal );
        }
        else if( nValType == ATTR_VAL_STRING )
        {
            JS_BIN_string( &binVal, &pStr );
            strMsg = pStr;
        }
        else if( nValType == ATTR_VAL_HEX )
        {
            JS_BIN_encodeHex( &binVal, &pStr );
            strMsg = pStr;
        }
        else if( nValType == ATTR_VAL_KEY_NAME )
        {
            long uVal = 0;
            memcpy( &uVal, binVal.pVal, binVal.nLen );
            strMsg = JS_PKCS11_GetCKKName( uVal );;
        }
        else if( nValType == ATTR_VAL_OBJECT_NAME )
        {
            long uVal = 0;
            memcpy( &uVal, binVal.pVal, binVal.nLen );
            strMsg = JS_PKCS11_GetCKOName( uVal );
        }
        else if( nValType == ATTR_VAL_LEN || nValType == ATTR_VAL_LONG )
        {
            long uLen = 0;
            memcpy( &uLen, binVal.pVal, sizeof(uLen));
            strMsg = QString("%1").arg( uLen );
        }
        else if( nValType == ATTR_VAL_DATE )
        {
            if( binVal.nLen >= 8 )
            {
                char    sYear[5];
                char    sMonth[3];
                char    sDay[3];
                CK_DATE *pDate = (CK_DATE *)binVal.pVal;

                memset( sYear, 0x00, sizeof(sYear));
                memset( sMonth, 0x00, sizeof(sMonth));
                memset( sDay, 0x00, sizeof(sDay));

                memcpy( sYear, pDate->year, 4 );
                memcpy( sMonth, pDate->month, 2 );
                memcpy( sDay, pDate->day, 2 );

                strMsg = QString( "%1-%2-%3").arg( sYear ).arg( sMonth ).arg(sDay);
            }
            else
            {
                JS_BIN_encodeHex( &binVal, &pStr );
                strMsg = pStr;
            }
        }
    }
    else
    {
        strMsg = QString( "[ERR] %1[%2]" ).arg( JS_PKCS11_GetErrorMsg(ret)).arg(ret);
        if( pnLen ) *pnLen = -1;
    }

    JS_BIN_reset( &binVal );
    if( pStr ) JS_free( pStr );

    return strMsg;
}

void ObjectViewDlg::setObject( long hObject )
{
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    mObjectText->setText( QString("%1").arg( hObject ));

    long uClass = stringAttribute( ATTR_VAL_LONG, CKA_CLASS, hObject ).toLong();
    mObjectLabel->setText( tr( "%1 Detail Information" ).arg( JS_PKCS11_GetCKOName(uClass)));

    for( int i = 0; i < kCommonAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kCommonAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mCommonTable->insertRow(i);
        mCommonTable->setRowHeight( i, 10 );
        mCommonTable->setItem( i, 0, item0 );
        mCommonTable->setItem( i, 1, item1 );
    }

    if( uClass == CKO_CERTIFICATE )
    {
        setCertificate( hObject );
    }
    else if( uClass == CKO_PRIVATE_KEY )
    {
        setPrivateKey( hObject );
    }
    else if( uClass == CKO_PUBLIC_KEY )
    {
        setPublicKey( hObject );
    }
    else if( uClass == CKO_SECRET_KEY )
    {
        setSecretKey( hObject );
    }
    else if( uClass == CKO_DATA )
    {
        setData( hObject );
    }
}

void ObjectViewDlg::setCertificate( long hObject )
{
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Certificate Common") );

    for( int i = 0; i < kCommonCertAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kCommonCertAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart1Table->insertRow(i);
        mPart1Table->setRowHeight( i, 10 );
        mPart1Table->setItem( i, 0, item0 );
        mPart1Table->setItem( i, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("X509 Certificate") );

    for( int i = 0; i < kX509CertAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kX509CertAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart2Table->insertRow(i);
        mPart2Table->setRowHeight( i, 10 );
        mPart2Table->setItem( i, 0, item0 );
        mPart2Table->setItem( i, 1, item1 );
    }
}

void ObjectViewDlg::setPublicKey( long hObject )
{
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Key Common") );

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kCommonKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart1Table->insertRow(i);
        mPart1Table->setRowHeight( i, 10 );
        mPart1Table->setItem( i, 0, item0 );
        mPart1Table->setItem( i, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("Public Key") );

    for( int i = 0; i < kPubKeyAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kPubKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart2Table->insertRow(i);
        mPart2Table->setRowHeight( i, 10 );
        mPart2Table->setItem( i, 0, item0 );
        mPart2Table->setItem( i, 1, item1 );
    }

    long uKeyType = stringAttribute( ATTR_VAL_LONG, CKA_KEY_TYPE, hObject ).toLong();
    mObjectToolBox->setItemEnabled( 3, true );

    if( uKeyType == CKK_RSA )
    {
        mObjectToolBox->setItemText( 3, tr("RSA Public Key") );

        for( int i = 0; i < kRSAKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kRSAKeyAttList.at(i);
            int row = 0;

            if( strName != "CKA_MODULUS" && strName != "CKA_PUBLIC_EXPONENT" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_EC )
    {
        mObjectToolBox->setItemText( 3, tr("ECDSA Public Key") );

        for( int i = 0; i < kECCKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_VALUE" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_DSA )
    {
        mObjectToolBox->setItemText( 3, tr("DSA Public Key") );

        for( int i = 0; i < kDSAKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kDSAKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_DH )
    {
        mObjectToolBox->setItemText( 3, tr("DH Public Key") );

        for( int i = 0; i < kDHKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kDHKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_EC_EDWARDS )
    {
        mObjectToolBox->setItemText( 3, tr("EC_EDWARDS Public Key") );

        for( int i = 0; i < kECCKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_VALUE" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
}

void ObjectViewDlg::setPrivateKey( long hObject )
{
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Key Common") );

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kCommonKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart1Table->insertRow(i);
        mPart1Table->setRowHeight( i, 10 );
        mPart1Table->setItem( i, 0, item0 );
        mPart1Table->setItem( i, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("Private Key") );

    for( int i = 0; i < kPriKeyAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kPriKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart2Table->insertRow(i);
        mPart2Table->setRowHeight( i, 10 );
        mPart2Table->setItem( i, 0, item0 );
        mPart2Table->setItem( i, 1, item1 );
    }

    long uKeyType = stringAttribute( ATTR_VAL_LONG, CKA_KEY_TYPE, hObject ).toLong();
    mObjectToolBox->setItemEnabled( 3, true );

    if( uKeyType == CKK_RSA )
    {
        mObjectToolBox->setItemText( 3, tr("RSA Private Key") );

        for( int i = 0; i < kRSAKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kRSAKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_EC )
    {
        mObjectToolBox->setItemText( 3, tr("ECDSA Private Key") );

        for( int i = 0; i < kECCKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_EC_POINT" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_DSA )
    {
        mObjectToolBox->setItemText( 3, tr("DSA Private Key") );

        for( int i = 0; i < kDSAKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kDSAKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_DH )
    {
        mObjectToolBox->setItemText( 3, tr("DH Private Key") );

        for( int i = 0; i < kDHKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kDHKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
    else if( uKeyType == CKK_EC_EDWARDS )
    {
        mObjectToolBox->setItemText( 3, tr("EC_EDWARDS Private Key") );

        for( int i = 0; i < kECCKeyAttList.size(); i++ )
        {
            int nLen = -1;
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_EC_POINT" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

            QTableWidgetItem* item0 = new QTableWidgetItem( strName );
            QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

            row = mPart3Table->rowCount();
            mPart3Table->insertRow(row);
            mPart3Table->setRowHeight( row, 10 );
            mPart3Table->setItem( row, 0, item0 );
            mPart3Table->setItem( i, 1, item1 );
        }
    }
}

void ObjectViewDlg::setSecretKey( long hObject )
{
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Key Common") );

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kCommonKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart1Table->insertRow(i);
        mPart1Table->setRowHeight( i, 10 );
        mPart1Table->setItem( i, 0, item0 );
        mPart1Table->setItem( i, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("Secret Key") );

    for( int i = 0; i < kSecretKeyAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kSecretKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart2Table->insertRow(i);
        mPart2Table->setRowHeight( i, 10 );
        mPart2Table->setItem( i, 0, item0 );
        mPart2Table->setItem( i, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 3, true );
    mObjectToolBox->setItemText( 3, tr("Secret Key Value") );

    for( int i = 0; i < kSecretValueAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kSecretValueAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart3Table->insertRow(i);
        mPart3Table->setRowHeight( i, 10 );
        mPart3Table->setItem( i, 0, item0 );
        mPart3Table->setItem( i, 1, item1 );
    }
}

void ObjectViewDlg::setData( long hObject )
{
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Data") );

    for( int i = 0; i < kDataAttList.size(); i++ )
    {
        int nLen = -1;
        int nType = -1;
        QString strName = kDataAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &nLen );

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        mPart1Table->insertRow(i);
        mPart1Table->setRowHeight( i, 10 );
        mPart1Table->setItem( i, 0, item0 );
        mPart1Table->setItem( i, 1, item1 );
    }

}
