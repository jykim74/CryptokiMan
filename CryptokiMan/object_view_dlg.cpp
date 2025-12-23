#include <QMenu>

#include "object_view_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "edit_attribute_dlg.h"

ObjectViewDlg::ObjectViewDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mReloadBtn, SIGNAL(clicked()), this, SLOT(clickReload()));

    connect( mCommonTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showCommonContextMenu(QPoint)));
    connect( mPart1Table, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showPart1ContextMenu(QPoint)));
    connect( mPart2Table, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showPart2ContextMenu(QPoint)));
    connect( mPart3Table, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showPart3ContextMenu(QPoint)));

    connect( mCommonTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickCommonField(QModelIndex)));
    connect( mPart1Table, SIGNAL(clicked(QModelIndex)), this, SLOT(clickPart1Field(QModelIndex)));
    connect( mPart2Table, SIGNAL(clicked(QModelIndex)), this, SLOT(clickPart2Field(QModelIndex)));
    connect( mPart3Table, SIGNAL(clicked(QModelIndex)), this, SLOT(clickPart3Field(QModelIndex)));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mCommonTab->layout()->setSpacing(5);
    mCommonTab->layout()->setMargin(5);
    mPart1Tab->layout()->setSpacing(5);
    mPart1Tab->layout()->setMargin(5);
    mPart2Tab->layout()->setSpacing(5);
    mPart2Tab->layout()->setMargin(5);
    mPart3Tab->layout()->setSpacing(5);
    mPart3Tab->layout()->setMargin(5);
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
        mSlotInfoText->setText( getSlotInfo( slot_info_ ) );
        mSlotInfoText->setCursorPosition(0);
        mSlotBtn->setIcon( getSlotIcon( slot_info_ ) );
    }
}

void ObjectViewDlg::initialize()
{

}

void ObjectViewDlg::initUI()
{
    int nWidth = (width() * 3)/10;

    QStringList sBaseLabels = { tr("Field"), tr("Value") };
    QStringList sFieldTypes = { tr("All"), tr("Version1 Only"), tr("Extension Only"), tr("Critical Extension Only"), tr("Attribute Only") };

    mCommonTable->clear();
    mCommonTable->horizontalHeader()->setStretchLastSection(true);
    mCommonTable->setColumnCount(2);
    mCommonTable->setHorizontalHeaderLabels( sBaseLabels );
    mCommonTable->verticalHeader()->setVisible(false);
    mCommonTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCommonTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mCommonTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCommonTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCommonTable->setColumnWidth( 0, nWidth );

    mPart1Table->clear();
    mPart1Table->horizontalHeader()->setStretchLastSection(true);
    mPart1Table->setColumnCount(2);
    mPart1Table->setHorizontalHeaderLabels( sBaseLabels );
    mPart1Table->verticalHeader()->setVisible(false);
    mPart1Table->horizontalHeader()->setStyleSheet( kTableStyle );
    mPart1Table->setSelectionMode(QAbstractItemView::SingleSelection);
    mPart1Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPart1Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mPart1Table->setColumnWidth( 0, nWidth );

    mPart2Table->clear();
    mPart2Table->horizontalHeader()->setStretchLastSection(true);
    mPart2Table->setColumnCount(2);
    mPart2Table->setHorizontalHeaderLabels( sBaseLabels );
    mPart2Table->verticalHeader()->setVisible(false);
    mPart2Table->horizontalHeader()->setStyleSheet( kTableStyle );
    mPart2Table->setSelectionMode(QAbstractItemView::SingleSelection);
    mPart2Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPart2Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mPart2Table->setColumnWidth( 0, nWidth );

    mPart3Table->clear();
    mPart3Table->horizontalHeader()->setStretchLastSection(true);
    mPart3Table->setColumnCount(2);
    mPart3Table->setHorizontalHeaderLabels( sBaseLabels );
    mPart3Table->verticalHeader()->setVisible(false);
    mPart3Table->horizontalHeader()->setStyleSheet( kTableStyle );
    mPart3Table->setSelectionMode(QAbstractItemView::SingleSelection);
    mPart3Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPart3Table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mPart3Table->setColumnWidth( 0, nWidth );

    mObjectToolBox->setItemEnabled( 1, false );
    mObjectToolBox->setItemEnabled( 2, false );
    mObjectToolBox->setItemEnabled( 3, false );

    mObjectToolBox->setItemText( 1, tr("NA"));
    mObjectToolBox->setItemText( 2, tr("NA"));
    mObjectToolBox->setItemText( 3, tr("NA"));
}

void ObjectViewDlg::editCommonObjectValue()
{
    QModelIndex idx = mCommonTable->currentIndex();
    QTableWidgetItem *item = mCommonTable->item( idx.row(), 0 );

    long hHandle = mObjectText->text().toLong();

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    EditAttributeDlg editAttribute;
    editAttribute.setSlotIndex( slot_index_ );
    editAttribute.setObjectID( hHandle );
    editAttribute.setObjectType( data_type_ );
    editAttribute.setAttrName( item->text() );
    editAttribute.exec();

    if( editAttribute.isChanged() == true )
    {
        int ret = 0;
        CK_ATTRIBUTE_TYPE uAttType = JS_PKCS11_GetCKAType( item->text().toStdString().c_str() );
        long nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hHandle, &ret );
        QTableWidgetItem *item1 = mCommonTable->item( idx.row(), 1 );
        if( item1 == NULL ) return;
        item1->setText( strValue );
    }
}

void ObjectViewDlg::editPart1ObjectValue()
{
    QModelIndex idx = mPart1Table->currentIndex();
    QTableWidgetItem *item = mPart1Table->item( idx.row(), 0 );
    long hHandle = mObjectText->text().toLong();

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    EditAttributeDlg editAttribute;
    editAttribute.setSlotIndex( slot_index_ );
    editAttribute.setObjectID( hHandle);
    editAttribute.setObjectType( data_type_ );
    editAttribute.setAttrName( item->text() );
    editAttribute.exec();

    if( editAttribute.isChanged() == true )
    {
        int ret = 0;
        CK_ATTRIBUTE_TYPE uAttType = JS_PKCS11_GetCKAType( item->text().toStdString().c_str() );
        long nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hHandle, &ret );
        QTableWidgetItem *item1 = mPart1Table->item( idx.row(), 1 );
        if( item1 == NULL ) return;
        item1->setText( strValue );
    }
}

void ObjectViewDlg::editPart2ObjectValue()
{
    QModelIndex idx = mPart2Table->currentIndex();
    QTableWidgetItem *item = mPart2Table->item( idx.row(), 0 );
    long hHandle = mObjectText->text().toLong();

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    EditAttributeDlg editAttribute;
    editAttribute.setSlotIndex( slot_index_ );
    editAttribute.setObjectID( hHandle );
    editAttribute.setObjectType( data_type_ );
    editAttribute.setAttrName( item->text() );
    editAttribute.exec();

    if( editAttribute.isChanged() == true )
    {
        int ret = 0;
        CK_ATTRIBUTE_TYPE uAttType = JS_PKCS11_GetCKAType( item->text().toStdString().c_str() );
        long nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hHandle, &ret );
        QTableWidgetItem *item1 = mPart2Table->item( idx.row(), 1 );
        if( item1 == NULL ) return;
        item1->setText( strValue );
    }
}

void ObjectViewDlg::editPart3ObjectValue()
{
    QModelIndex idx = mPart3Table->currentIndex();
    QTableWidgetItem *item = mPart3Table->item( idx.row(), 0 );
    long hHandle = mObjectText->text().toLong();

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    EditAttributeDlg editAttribute;
    editAttribute.setSlotIndex( slot_index_ );
    editAttribute.setObjectID( hHandle );
    editAttribute.setObjectType( data_type_ );
    editAttribute.setAttrName( item->text() );
    editAttribute.exec();

    if( editAttribute.isChanged() == true )
    {
        int ret = 0;
        CK_ATTRIBUTE_TYPE uAttType = JS_PKCS11_GetCKAType( item->text().toStdString().c_str() );
        long nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hHandle, &ret );
        QTableWidgetItem *item1 = mPart3Table->item( idx.row(), 1 );
        if( item1 == NULL ) return;
        item1->setText( strValue );
    }
}

void ObjectViewDlg::showCommonContextMenu( QPoint point )
{
    QModelIndex idx = mCommonTable->currentIndex();
    QTableWidgetItem *item = mCommonTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    QMenu *menu = new QMenu(this);
    QAction *editAct = new QAction( tr( "Edit" ), this );

    if( manApplet->isLicense() == false )
        editAct->setEnabled( false );

    connect( editAct, SIGNAL(triggered(bool)), this, SLOT(editCommonObjectValue()));

    menu->addAction( editAct );

    menu->popup( mCommonTable->viewport()->mapToGlobal( point ));
}

void ObjectViewDlg::showPart1ContextMenu( QPoint point )
{
    QModelIndex idx = mPart1Table->currentIndex();
    QTableWidgetItem *item = mPart1Table->item( idx.row(), 0 );
    if( item == NULL ) return;

    QMenu *menu = new QMenu(this);
    QAction *editAct = new QAction( tr( "Edit" ), this );

    if( manApplet->isLicense() == false )
        editAct->setEnabled( false );

    connect( editAct, SIGNAL(triggered(bool)), this, SLOT(editPart1ObjectValue()));

    menu->addAction( editAct );

    menu->popup( mPart1Table->viewport()->mapToGlobal( point ));
}

void ObjectViewDlg::showPart2ContextMenu( QPoint point )
{
    QModelIndex idx = mPart2Table->currentIndex();
    QTableWidgetItem *item = mPart2Table->item( idx.row(), 0 );
    if( item == NULL ) return;

    QMenu *menu = new QMenu(this);
    QAction *editAct = new QAction( tr( "Edit" ), this );

    if( manApplet->isLicense() == false )
        editAct->setEnabled( false );

    connect( editAct, SIGNAL(triggered(bool)), this, SLOT(editPart2ObjectValue()));

    menu->addAction( editAct );

    menu->popup( mPart2Table->viewport()->mapToGlobal( point ));
}

void ObjectViewDlg::showPart3ContextMenu( QPoint point )
{
    QModelIndex idx = mPart3Table->currentIndex();
    QTableWidgetItem *item = mPart3Table->item( idx.row(), 0 );
    if( item == NULL ) return;

    QMenu *menu = new QMenu(this);
    QAction *editAct = new QAction( tr( "Edit" ), this );

    if( manApplet->isLicense() == false )
        editAct->setEnabled( false );

    connect( editAct, SIGNAL(triggered(bool)), this, SLOT(editPart3ObjectValue()));

    menu->addAction( editAct );

    menu->popup( mPart3Table->viewport()->mapToGlobal( point ));
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

QString ObjectViewDlg::stringAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj, int *pnRet )
{
    int ret = 0;

    char    *pStr = NULL;
    QString strMsg;
    BIN     binVal = {0,0};

    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObj, uAttribute, &binVal );

    *pnRet = ret;

    if( ret == CKR_OK )
    {
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
    }

    JS_BIN_reset( &binVal );
    if( pStr ) JS_free( pStr );

    return strMsg;
}

void ObjectViewDlg::setObject( long hObject )
{
    int ret = 0;
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    bool bVal = manApplet->settingsMgr()->displayValid();

    mObjectText->setText( QString("%1").arg( hObject ));

    long uClass = stringAttribute( ATTR_VAL_LONG, CKA_CLASS, hObject, &ret ).toLong();
    mObjectLabel->setText( tr( "%1 Detail Information" ).arg( JS_PKCS11_GetCKOName(uClass)));

    for( int i = 0; i < kCommonAttList.size(); i++ )
    {
        int nType = -1;

        QString strName = kCommonAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mCommonTable->rowCount();
        mCommonTable->insertRow( nRow );
        mCommonTable->setRowHeight( nRow, 10 );
        mCommonTable->setItem( nRow, 0, item0 );
        mCommonTable->setItem( nRow, 1, item1 );
    }

    if( uClass == CKO_CERTIFICATE )
    {
        mObjectToolBox->setItemIcon( 0, QIcon( ":/images/cert.png" ));
        mObjectBtn->setIcon( QIcon(":/images/cert.png") );
        setCertificate( hObject );
        data_type_ = OBJ_CERT_IDX;
    }
    else if( uClass == CKO_PRIVATE_KEY )
    {
        mObjectToolBox->setItemIcon( 0, QIcon( ":/images/prikey.png" ));
        mObjectBtn->setIcon( QIcon(":/images/prikey.png") );
        setPrivateKey( hObject );
        data_type_ = OBJ_PRIKEY_IDX;
    }
    else if( uClass == CKO_PUBLIC_KEY )
    {
        mObjectToolBox->setItemIcon( 0, QIcon( ":/images/pubkey.png" ));
        mObjectBtn->setIcon( QIcon(":/images/pubkey.png") );
        setPublicKey( hObject );
        data_type_ = OBJ_PUBKEY_IDX;
    }
    else if( uClass == CKO_SECRET_KEY )
    {
        mObjectToolBox->setItemIcon( 0, QIcon( ":/images/key.png" ));
        mObjectBtn->setIcon( QIcon(":/images/key.png") );
        setSecretKey( hObject );
        data_type_ = OBJ_SECRET_IDX;
    }
    else if( uClass == CKO_DATA )
    {
        mObjectToolBox->setItemIcon( 0, QIcon( ":/images/data_add.png" ));
        mObjectBtn->setIcon( QIcon(":/images/data_add.png") );
        setData( hObject );
        data_type_ = OBJ_DATA_IDX;
    }
}

void ObjectViewDlg::setCertificate( long hObject )
{
    int ret = -1;
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    bool bVal = manApplet->settingsMgr()->displayValid();

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Certificate Common") );
    mObjectToolBox->setItemIcon( 1, QIcon( ":/images/cert.png" ));

    for( int i = 0; i < kCommonCertAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kCommonCertAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart1Table->rowCount();
        mPart1Table->insertRow( nRow );
        mPart1Table->setRowHeight( nRow, 10 );
        mPart1Table->setItem( nRow, 0, item0 );
        mPart1Table->setItem( nRow, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("X509 Certificate") );
    mObjectToolBox->setItemIcon( 2, QIcon( ":/images/cert.png" ));

    for( int i = 0; i < kX509CertAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kX509CertAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart2Table->rowCount();
        mPart2Table->insertRow(i);
        mPart2Table->setRowHeight( i, 10 );
        mPart2Table->setItem( i, 0, item0 );
        mPart2Table->setItem( i, 1, item1 );
    }
}

void ObjectViewDlg::setPublicKey( long hObject )
{
    int ret = -1;
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    bool bVal = manApplet->settingsMgr()->displayValid();

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Key Common") );
    mObjectToolBox->setItemIcon( 1, QIcon( ":/images/pubkey.png" ));

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kCommonKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart1Table->rowCount();
        mPart1Table->insertRow( nRow );
        mPart1Table->setRowHeight( nRow, 10 );
        mPart1Table->setItem( nRow, 0, item0 );
        mPart1Table->setItem( nRow, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("Public Key") );
    mObjectToolBox->setItemIcon( 2, QIcon( ":/images/pubkey.png" ));

    for( int i = 0; i < kPubKeyAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kPubKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart2Table->rowCount();
        mPart2Table->insertRow( nRow );
        mPart2Table->setRowHeight( nRow, 10 );
        mPart2Table->setItem( nRow, 0, item0 );
        mPart2Table->setItem( nRow, 1, item1 );
    }

    long uKeyType = stringAttribute( ATTR_VAL_LONG, CKA_KEY_TYPE, hObject, &ret ).toLong();
    mObjectToolBox->setItemEnabled( 3, true );
    mObjectToolBox->setItemIcon( 3, QIcon( ":/images/pubkey.png" ));

    if( uKeyType == CKK_RSA )
    {
        mObjectToolBox->setItemText( 3, tr("RSA Public Key") );

        for( int i = 0; i < kRSAKeyAttList.size(); i++ )
        {
            int nType = -1;
            QString strName = kRSAKeyAttList.at(i);
            int row = 0;

            if( strName != "CKA_MODULUS" && strName != "CKA_PUBLIC_EXPONENT" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_VALUE" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kDSAKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kDHKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_VALUE" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
    int ret = -1;
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    bool bVal = manApplet->settingsMgr()->displayValid();

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Key Common") );
    mObjectToolBox->setItemIcon( 1, QIcon( ":/images/prikey.png" ));

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kCommonKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart1Table->rowCount();
        mPart1Table->insertRow( nRow );
        mPart1Table->setRowHeight( nRow, 10 );
        mPart1Table->setItem( nRow, 0, item0 );
        mPart1Table->setItem( nRow, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("Private Key") );
    mObjectToolBox->setItemIcon( 2, QIcon( ":/images/prikey.png" ));

    for( int i = 0; i < kPriKeyAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kPriKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart2Table->rowCount();
        mPart2Table->insertRow( nRow );
        mPart2Table->setRowHeight( nRow, 10 );
        mPart2Table->setItem( nRow, 0, item0 );
        mPart2Table->setItem( nRow, 1, item1 );
    }

    long uKeyType = stringAttribute( ATTR_VAL_LONG, CKA_KEY_TYPE, hObject, &ret ).toLong();
    mObjectToolBox->setItemEnabled( 3, true );
    mObjectToolBox->setItemIcon( 3, QIcon( ":/images/prikey.png" ));

    if( uKeyType == CKK_RSA )
    {
        mObjectToolBox->setItemText( 3, tr("RSA Private Key") );

        for( int i = 0; i < kRSAKeyAttList.size(); i++ )
        {
            int nType = -1;
            QString strName = kRSAKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_EC_POINT" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kDSAKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kDHKeyAttList.at(i);
            int row = 0;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
            int nType = -1;
            QString strName = kECCKeyAttList.at(i);
            int row = 0;

            if( strName == "CKA_EC_POINT" )
                continue;

            uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

            nType = CryptokiAPI::getAttrType( uAttType );
            QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

            if( bVal == true && ret != CKR_OK ) continue;

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
    int ret = -1;
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    bool bVal = manApplet->settingsMgr()->displayValid();

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Key Common") );
    mObjectToolBox->setItemIcon( 1, QIcon( ":/images/key.png" ));

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kCommonKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart1Table->rowCount();
        mPart1Table->insertRow( nRow );
        mPart1Table->setRowHeight( nRow, 10 );
        mPart1Table->setItem( nRow, 0, item0 );
        mPart1Table->setItem( nRow, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 2, true );
    mObjectToolBox->setItemText( 2, tr("Secret Key") );
    mObjectToolBox->setItemIcon( 2, QIcon( ":/images/key.png" ));

    for( int i = 0; i < kSecretKeyAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kSecretKeyAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart2Table->rowCount();
        mPart2Table->insertRow( nRow );
        mPart2Table->setRowHeight( nRow, 10 );
        mPart2Table->setItem( nRow, 0, item0 );
        mPart2Table->setItem( nRow, 1, item1 );
    }

    mObjectToolBox->setItemEnabled( 3, true );
    mObjectToolBox->setItemText( 3, tr("Secret Key Value") );
    mObjectToolBox->setItemIcon( 3, QIcon( ":/images/key.png" ));

    for( int i = 0; i < kSecretValueAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kSecretValueAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart3Table->rowCount();
        mPart3Table->insertRow( nRow );
        mPart3Table->setRowHeight( nRow, 10 );
        mPart3Table->setItem( nRow, 0, item0 );
        mPart3Table->setItem( nRow, 1, item1 );
    }
}

void ObjectViewDlg::setData( long hObject )
{
    int ret = -1;
    CK_ATTRIBUTE_TYPE uAttType = -1;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    if( pAPI == NULL ) return;

    bool bVal = manApplet->settingsMgr()->displayValid();

    mObjectToolBox->setItemEnabled( 1, true );
    mObjectToolBox->setItemText( 1, tr("Data") );
    mObjectToolBox->setItemIcon( 1, QIcon( ":/images/data_add.png" ));

    for( int i = 0; i < kDataAttList.size(); i++ )
    {
        int nType = -1;
        QString strName = kDataAttList.at(i);
        uAttType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );

        nType = CryptokiAPI::getAttrType( uAttType );
        QString strValue = stringAttribute( nType, uAttType, hObject, &ret );

        if( bVal == true && ret != CKR_OK ) continue;

        QTableWidgetItem* item0 = new QTableWidgetItem( strName );
        QTableWidgetItem* item1 = new QTableWidgetItem( strValue );

        int nRow = mPart1Table->rowCount();
        mPart1Table->insertRow( nRow );
        mPart1Table->setRowHeight( nRow, 10 );
        mPart1Table->setItem( nRow, 0, item0 );
        mPart1Table->setItem( nRow, 1, item1 );
    }

}
