#include <QStringList>
#include <QMenu>

#include "hsm_man_dlg.h"
#include "common.h"
#include "man_applet.h"
#include "settings_mgr.h"
#include "cryptoki_api.h"
#include "js_pkcs11.h"
#include "mech_mgr.h"
#include "mainwindow.h"
#include "js_pki_tools.h"
#include "cert_info_dlg.h"
#include "pri_key_info_dlg.h"
#include "export_dlg.h"
#include "p11_work.h"
#include "secret_info_dlg.h"
#include "sign_dlg.h"
#include "verify_dlg.h"
#include "encrypt_dlg.h"
#include "decrypt_dlg.h"
#include "object_view_dlg.h"

const QStringList kUsageList = { "Any", "Sign", "Verify", "Encrypt", "Decrypt", "Wrap", "Unwrap", "Derive" };

HsmManDlg::HsmManDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;

    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mUsageCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeUsage()));

    connect( mCertTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotCertTableMenuRequested(QPoint)));
    connect( mPublicTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotPubKeyTableMenuRequested(QPoint)));
    connect( mPrivateTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotPriKeyTableMenuRequested(QPoint)));
    connect( mSecretTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotSecretTableMenuRequested(QPoint)));

    connect( mTabWidget, SIGNAL(currentChanged(int)), this, SLOT(changeTab(int)));
    connect( mCertKeyPairCheck, SIGNAL(clicked()), this, SLOT(loadCertList()));
    connect( mPublicTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadPublicList()));
    connect( mPrivateTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadPrivateList()));
    connect( mSecretTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadSecretList()));

    connect( mCertObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickCertObjectView()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDeleteBtn, SIGNAL(clicked()), this, SLOT(clickCertDelete()));
    connect( mCertExportBtn, SIGNAL(clicked()), this, SLOT(clickCertExport()));
    connect( mCertDeleteKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCertDeleteKeyPair()));

    connect( mPublicObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickPublicObjectView()));
    connect( mPublicViewBtn, SIGNAL(clicked()), this, SLOT(clickPublicView()));
    connect( mPublicDeleteBtn, SIGNAL(clicked()), this, SLOT(clickPublicDelete()));
    connect( mPublicExportBtn, SIGNAL(clicked()), this, SLOT(clickPublicExport()));
    connect( mPublicVerifyBtn, SIGNAL(clicked()), this, SLOT(clickPublicVerify()));
    connect( mPublicEncryptBtn, SIGNAL(clicked()), this, SLOT(clickPublicEncrypt()));

    connect( mPrivateObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickPrivateObjectView()));
    connect( mPrivateViewBtn, SIGNAL(clicked()), this, SLOT(clickPrivateView()));
    connect( mPrivateDeleteBtn, SIGNAL(clicked()), this, SLOT(clickPrivateDelete()));
    connect( mPrivateExportBtn, SIGNAL(clicked()), this, SLOT(clickPrivateExport()));
    connect( mPrivateSignBtn, SIGNAL(clicked()), this, SLOT(clickPrivateSign()));
    connect( mPrivateDecryptBtn, SIGNAL(clicked()), this, SLOT(clickPrivateDecrypt()));

    connect( mSecretObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickSecretObjectView()));
    connect( mSecretViewBtn, SIGNAL(clicked()), this, SLOT(clickSecretView()));
    connect( mSecretDeleteBtn, SIGNAL(clicked()), this, SLOT(clickSecretDelete()));
    connect( mSecretEncryptBtn, SIGNAL(clicked()), this, SLOT(clickSecretEncrypt()));
    connect( mSecretDecryptBtn, SIGNAL(clicked()), this, SLOT(clickSecretDecrypt()));
    connect( mSecretSignBtn, SIGNAL(clicked()), this, SLOT(clickSecretSign()));
    connect( mSecretVerifyBtn, SIGNAL(clicked()), this, SLOT(clickSecretVerify()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mCertTab->layout()->setSpacing(5);
    mCertTab->layout()->setMargin(5);
    mCertGroup->layout()->setSpacing(5);
    mCertGroup->layout()->setMargin(5);

    mPublicTab->layout()->setSpacing(5);
    mPublicTab->layout()->setMargin(5);
    mPublicGroup->layout()->setSpacing(5);
    mPublicGroup->layout()->setMargin(5);

    mPrivateTab->layout()->setSpacing(5);
    mPrivateTab->layout()->setMargin(5);
    mPrivateGroup->layout()->setSpacing(5);
    mPrivateGroup->layout()->setMargin(5);

    mSecretTab->layout()->setSpacing(5);
    mSecretTab->layout()->setMargin(5);
    mSecretGroup->layout()->setSpacing(5);
    mSecretGroup->layout()->setMargin(5);
#endif



    mOKBtn->setDefault(true);
    mOKBtn->hide();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

HsmManDlg::~HsmManDlg()
{

}

void HsmManDlg::setMode( int nMode, int nUsage )
{
    if( nMode != HsmModeManage )
    {
        mCertGroup->hide();
        mPublicGroup->hide();
        mPrivateGroup->hide();
        mSecretGroup->hide();

        mOKBtn->show();

        mTabWidget->setTabEnabled( TAB_CERT_IDX, false );
        mTabWidget->setTabEnabled( TAB_PUBLIC_IDX, false );
        mTabWidget->setTabEnabled( TAB_PRIVATE_IDX, false );
        mTabWidget->setTabEnabled( TAB_SECRET_IDX, false );

        connect( mCertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mPublicTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mPrivateTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mSecretTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
    }
    else
    {
        connect( mCertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickCertView()));
        connect( mPublicTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickPublicView()));
        connect( mPrivateTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickPrivateView()));
        connect( mSecretTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickSecretView()));
    }

    if( nMode == HsmModeSelectCert )
    {
        mTabWidget->setCurrentIndex( TAB_CERT_IDX );
        mTabWidget->setTabEnabled( TAB_CERT_IDX, true );
    }
    else if( nMode == HsmModeSelectPublicKey )
    {
        mTabWidget->setCurrentIndex( TAB_PUBLIC_IDX );
        mTabWidget->setTabEnabled( TAB_PUBLIC_IDX, true );
    }
    else if( nMode == HsmModeSelectPrivateKey )
    {
        mTabWidget->setCurrentIndex( TAB_PRIVATE_IDX );
        mTabWidget->setTabEnabled( TAB_PRIVATE_IDX, true );
    }
    else if( nMode == HsmModeSelectSecretKey )
    {
        mTabWidget->setCurrentIndex( TAB_SECRET_IDX );
        mTabWidget->setTabEnabled( TAB_SECRET_IDX, true );
    }
    else if( nMode == HsmModeSelectDeriveKey )
    {
        mTabWidget->setCurrentIndex( TAB_PRIVATE_IDX );
        mTabWidget->setTabEnabled( TAB_PRIVATE_IDX, true );
        mTabWidget->setTabEnabled( TAB_SECRET_IDX, true );
    }

    if( nMode != HsmModeManage && nMode != HsmModeSelectCert )
    {
        if( nUsage == HsmUsageSign )
            mUsageCombo->setCurrentText( "Sign" );
        else if( nUsage == HsmUsageVerify )
            mUsageCombo->setCurrentText( "Verify" );
        else if( nUsage == HsmUsageEncrypt )
            mUsageCombo->setCurrentText( "Encrypt" );
        else if( nUsage == HsmUsageDecrypt )
            mUsageCombo->setCurrentText( "Decrypt" );
        else if( nUsage == HsmUsageWrap )
            mUsageCombo->setCurrentText( "Wrap" );
        else if( nUsage == HsmUsageUnwrap )
            mUsageCombo->setCurrentText( "Unwrap" );
        else if( nUsage == HsmUsageDerive )
            mUsageCombo->setCurrentText( "Derive" );
    }
}

void HsmManDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void HsmManDlg::setTabIdx( int nIdx )
{
    if( nIdx < 0 || nIdx > TAB_SECRET_IDX )
        return;

    mTabWidget->setCurrentIndex( nIdx );
}

void HsmManDlg::setSlotIndex(int index)
{
    if( index < 0 ) return;

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

void HsmManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void HsmManDlg::closeEvent(QCloseEvent *event )
{

}

void HsmManDlg::slotCertTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *viewAct = new QAction( tr( "View" ), this );
    QAction *deleteAct = new QAction( tr( "Delete" ), this );
    QAction *exportAct = new QAction( tr("Export"), this );
    QAction *objectViewAct = new QAction( tr("Object View"), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(clickCertView()));
    connect( deleteAct, SIGNAL(triggered()), this, SLOT(clickCertDelete()));
    connect( exportAct, SIGNAL(triggered()), this, SLOT(clickCertExport()));
    connect( objectViewAct, SIGNAL(triggered()), this, SLOT(clickCertObjectView()));

    menu->addAction( viewAct );
    menu->addAction( deleteAct );
    menu->addAction( exportAct );
    menu->addAction( objectViewAct );

    menu->popup( mCertTable->viewport()->mapToGlobal(pos));
}

void HsmManDlg::slotPubKeyTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *viewAct = new QAction( tr( "View" ), this );
    QAction *deleteAct = new QAction( tr( "Delete" ), this );
    QAction *exportAct = new QAction( tr("Export"), this );
    QAction *objectViewAct = new QAction( tr("Object View"), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(clickPublicView()));
    connect( deleteAct, SIGNAL(triggered()), this, SLOT(clickPublicDelete()));
    connect( exportAct, SIGNAL(triggered()), this, SLOT(clickPublicExport()));
    connect( objectViewAct, SIGNAL(triggered()), this, SLOT(clickPublicObjectView()));

    menu->addAction( viewAct );
    menu->addAction( deleteAct );
    menu->addAction( exportAct );
    menu->addAction( objectViewAct );

    menu->popup( mPublicTable->viewport()->mapToGlobal(pos));
}

void HsmManDlg::slotPriKeyTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *viewAct = new QAction( tr( "View" ), this );
    QAction *deleteAct = new QAction( tr( "Delete" ), this );
    QAction *exportAct = new QAction( tr("Export"), this );
    QAction *objectViewAct = new QAction( tr("Object View"), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(clickPrivateView()));
    connect( deleteAct, SIGNAL(triggered()), this, SLOT(clickPrivateDelete()));
    connect( exportAct, SIGNAL(triggered()), this, SLOT(clickPrivateExport()));
    connect( objectViewAct, SIGNAL(triggered()), this, SLOT(clickPrivateObjectView()));

    menu->addAction( viewAct );
    menu->addAction( deleteAct );
    menu->addAction( exportAct );
    menu->addAction( objectViewAct );

    menu->popup( mPrivateTable->viewport()->mapToGlobal(pos));
}

void HsmManDlg::slotSecretTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *viewAct = new QAction( tr( "View" ), this );
    QAction *deleteAct = new QAction( tr( "Delete" ), this );
    QAction *objectViewAct = new QAction( tr("Object View"), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(clickSecretView()));
    connect( deleteAct, SIGNAL(triggered()), this, SLOT(clickSecretDelete()));
    connect( objectViewAct, SIGNAL(triggered()), this, SLOT(clickSecretObjectView()));

    menu->addAction( viewAct );
    menu->addAction( deleteAct );
    menu->addAction( objectViewAct );

    menu->popup( mSecretTable->viewport()->mapToGlobal(pos));
}

void HsmManDlg::changeTab( int index )
{
    mUsageCombo->setEnabled(true);

    if( index == 0 )
    {
        loadCertList();
        mUsageCombo->setEnabled(false);
    }
    else if( index == 1 )
    {
        loadPublicList();
    }
    else if( index == 2 )
    {
        loadPrivateList();
    }
    else if( index == 3 )
    {
        loadSecretList();
    }
}

void HsmManDlg::changeUsage()
{
    int index = mTabWidget->currentIndex();
    changeTab( index );
}

void HsmManDlg::initUI()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 8/10;
#else
    int nWidth = width() * 8/10;
#endif

    mUsageCombo->addItems( kUsageList );
    mTabWidget->setCurrentIndex(0);

    QStringList sCertLabels = { tr("Label"), tr("Handle"), tr("Subject DN") };

    mCertTable->horizontalHeader()->setStretchLastSection(true);
    mCertTable->setColumnCount( sCertLabels.size() );
    mCertTable->setHorizontalHeaderLabels( sCertLabels );
    mCertTable->verticalHeader()->setVisible(false);
    mCertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCertTable->setColumnWidth( 0, nWidth * 5/10 );
    mCertTable->setColumnWidth( 1, nWidth * 2/10 );
    mCertTable->setColumnWidth( 2, nWidth * 2/10 );

    QStringList sTableLabels = { tr( "Name" ), tr( "Algorithm"), tr( "Handle"), tr( "ID") };

    mPublicTable->horizontalHeader()->setStretchLastSection(true);
    mPublicTable->setColumnCount( sTableLabels.size() );
    mPublicTable->setHorizontalHeaderLabels( sTableLabels );
    mPublicTable->verticalHeader()->setVisible(false);
    mPublicTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mPublicTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPublicTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mPublicTable->setColumnWidth( 0, nWidth * 5/10 );
    mPublicTable->setColumnWidth( 1, nWidth * 2/10 );
    mPublicTable->setColumnWidth( 2, nWidth * 1/10 );

    mPrivateTable->horizontalHeader()->setStretchLastSection(true);
    mPrivateTable->setColumnCount( sTableLabels.size() );
    mPrivateTable->setHorizontalHeaderLabels( sTableLabels );
    mPrivateTable->verticalHeader()->setVisible(false);
    mPrivateTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mPrivateTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPrivateTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mPrivateTable->setColumnWidth( 0, nWidth * 5/10 );
    mPrivateTable->setColumnWidth( 1, nWidth * 2/10 );
    mPrivateTable->setColumnWidth( 2, nWidth * 1/10 );

    mSecretTable->horizontalHeader()->setStretchLastSection(true);
    mSecretTable->setColumnCount( sTableLabels.size() );
    mSecretTable->setHorizontalHeaderLabels( sTableLabels );
    mSecretTable->verticalHeader()->setVisible(false);
    mSecretTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mSecretTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mSecretTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mSecretTable->setColumnWidth( 0, nWidth * 5/10 );
    mSecretTable->setColumnWidth( 1, nWidth * 2/10 );
    mSecretTable->setColumnWidth( 2, nWidth * 1/10 );

    mPublicTypeCombo->addItem( "Any" );
    mPublicTypeCombo->addItems( kAsymTypeList );

    mPrivateTypeCombo->addItem( "Any" );
    mPrivateTypeCombo->addItems( kAsymTypeList );

    mSecretTypeCombo->addItem( "Any" );
    mSecretTypeCombo->addItems( kSymKeyList );
}

void HsmManDlg::initialize()
{
    int index = mTabWidget->currentIndex();

    if( index == 0 )
        loadCertList();
    else if( index == 1 )
        loadPublicList();
    else if( index == 2 )
        loadPrivateList();
    else if( index == 3 )
        loadSecretList();
}

void HsmManDlg::setUsageTemplate( CK_ATTRIBUTE sTemplate[], long& uCount )
{
    QString strUsage = mUsageCombo->currentText();

    if( strUsage != "Any" )
    {
        if( strUsage == "Sign" )
            sTemplate[uCount].type = CKA_SIGN;
        else if( strUsage == "Verify" )
            sTemplate[uCount].type = CKA_VERIFY;
        else if( strUsage == "Encrypt" )
            sTemplate[uCount].type = CKA_ENCRYPT;
        else if( strUsage == "Decrypt" )
            sTemplate[uCount].type = CKA_DECRYPT;
        else if( strUsage == "Wrap" )
            sTemplate[uCount].type = CKA_WRAP;
        else if( strUsage == "Unwrap" )
            sTemplate[uCount].type = CKA_UNWRAP;
        else if( strUsage == "Derive" )
            sTemplate[uCount].type = CKA_DERIVE;

        sTemplate[uCount].pValue = &kTrue;
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }
}

void HsmManDlg::loadCertList()
{
#if 1
    int rv;
    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binDN = {0,0};

    CryptokiAPI *pP11 = manApplet->cryptokiAPI();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE hObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    mCertTable->setRowCount(0);

    rv = pP11->FindObjectsInit( slot_info_.getSessionHandle(), sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjects( slot_info_.getSessionHandle(), hObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjectsFinal( slot_info_.getSessionHandle() );
    if( rv != CKR_OK ) goto end;


    for( int i = 0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        char *pDN = NULL;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_SUBJECT, &binDN );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        if( binID.nLen < 1 ) continue;

        if( mCertKeyPairCheck->isChecked() == true )
        {
            long hPri = pP11->getHandle( slot_info_.getSessionHandle(), CKO_PRIVATE_KEY, &binID );
            if( hPri < 0 ) continue;

            long hPub = pP11->getHandle( slot_info_.getSessionHandle(), CKO_PUBLIC_KEY, &binID );
            if( hPub < 0 ) continue;
        }

        JS_BIN_string( &binLabel, &pLabel );
        JS_PKI_getTextDN( &binDN, &pDN );

        mCertTable->insertRow(0);
        mCertTable->setRowHeight(0, 10);
        QTableWidgetItem *item = new QTableWidgetItem( pLabel );
        item->setIcon(QIcon(":/images/cert.png"));

        QString strData = QString( "CERT:%1:%2" ).arg( hObjects[i] ).arg( getHexString( &binID ));
        item->setData(Qt::UserRole, strData);

        mCertTable->setItem(0, 0, item);
        mCertTable->setItem(0, 1, new QTableWidgetItem( QString("%1").arg( hObjects[i] )));
        mCertTable->setItem(0, 2, new QTableWidgetItem( QString("%1").arg( pDN)));

        if( pLabel )
        {
            JS_free( pLabel );
            pLabel = NULL;
        }

        if( pDN ) JS_free( pDN );
    }

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binDN );

    return;
#endif
}

void HsmManDlg::loadPublicList()
{
    int rv;

    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binKeyType = {0,0};

    if( slot_info_.getSessionHandle() < 0 ) return;

    CryptokiAPI *pP11 = manApplet->cryptokiAPI();


    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;

    CK_KEY_TYPE keyType = -1;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE hObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    mPublicTable->setRowCount(0);

    QString strType = mPublicTypeCombo->currentText();
    if( strType != "Any" )
    {
        keyType = JS_PKCS11_GetCKKType( strType.toStdString().c_str() );
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;
    }

    setUsageTemplate( sTemplate, uCount );

    rv = pP11->FindObjectsInit( slot_info_.getSessionHandle(), sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjects( slot_info_.getSessionHandle(), hObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjectsFinal( slot_info_.getSessionHandle() );
    if( rv != CKR_OK ) goto end;


    for( int i = 0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        long nKeyType = -1;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_KEY_TYPE, &binKeyType );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        if( binID.nLen < 1 ) continue;

        JS_BIN_string( &binLabel, &pLabel );
        memcpy( &nKeyType, binKeyType.pVal, binKeyType.nLen );

        mPublicTable->insertRow(0);
        mPublicTable->setRowHeight(0, 10);
        QTableWidgetItem *item = new QTableWidgetItem( pLabel );
        item->setIcon(QIcon(":/images/pubkey.png"));

        QString strData = QString( "PUB:%1:%2:%3" ).arg( hObjects[i] ).arg( getHexString( &binID )).arg( nKeyType );
        item->setData(Qt::UserRole, strData);

        mPublicTable->setItem(0, 0, item);
        mPublicTable->setItem(0,1, new QTableWidgetItem( QString( "%1").arg( JS_PKCS11_GetCKKName( nKeyType ))) );
        mPublicTable->setItem(0, 2, new QTableWidgetItem( QString("%1").arg( hObjects[i] )));
        mPublicTable->setItem(0, 3, new QTableWidgetItem( QString("%1").arg( getHexString( &binID ))));

        if( pLabel )
        {
            JS_free( pLabel );
            pLabel = NULL;
        }
    }

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binKeyType );

    return;
}

void HsmManDlg::loadPrivateList()
{
    int rv;
    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binKeyType = {0,0};

    if( slot_info_.getSessionHandle() < 0 ) return;

    CryptokiAPI *pP11 = manApplet->cryptokiAPI();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE hObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    mPrivateTable->setRowCount(0);

    CK_KEY_TYPE keyType = -1;
    QString strType = mPrivateTypeCombo->currentText();
    if( strType != "Any" )
    {
        keyType = JS_PKCS11_GetCKKType( strType.toStdString().c_str() );
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;
    }

    setUsageTemplate( sTemplate, uCount );

    rv = pP11->FindObjectsInit( slot_info_.getSessionHandle(), sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjects( slot_info_.getSessionHandle(), hObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjectsFinal( slot_info_.getSessionHandle() );
    if( rv != CKR_OK ) goto end;


    for( int i = 0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        long nKeyType = -1;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_KEY_TYPE, &binKeyType );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        if( binID.nLen < 1 ) continue;

        JS_BIN_string( &binLabel, &pLabel );
        memcpy( &nKeyType, binKeyType.pVal, binKeyType.nLen );

        mPrivateTable->insertRow(0);
        mPrivateTable->setRowHeight(0, 10);
        QTableWidgetItem *item = new QTableWidgetItem( pLabel );
        item->setIcon(QIcon(":/images/prikey.png"));

        QString strData = QString( "PRI:%1:%2:%3" ).arg( hObjects[i] ).arg( getHexString( &binID )).arg( nKeyType );
        item->setData(Qt::UserRole, strData);

        mPrivateTable->setItem(0, 0, item);
        mPrivateTable->setItem(0,1, new QTableWidgetItem( QString( "%1").arg( JS_PKCS11_GetCKKName( nKeyType ))) );
        mPrivateTable->setItem(0, 2, new QTableWidgetItem( QString("%1").arg( hObjects[i] )));
        mPrivateTable->setItem(0, 3, new QTableWidgetItem( QString("%1").arg( getHexString( &binID ))));

        if( pLabel )
        {
            JS_free( pLabel );
            pLabel = NULL;
        }
    }

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binKeyType );

    return;
}

void HsmManDlg::loadSecretList()
{
    int rv;
    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binKeyType = {0,0};

    if( slot_info_.getSessionHandle() < 0 ) return;

    CryptokiAPI *pP11 = manApplet->cryptokiAPI();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE hObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    mSecretTable->setRowCount(0);

    CK_KEY_TYPE keyType = -1;
    QString strType = mSecretTypeCombo->currentText();
    if( strType != "Any" )
    {
        keyType = JS_PKCS11_GetCKKType( strType.toStdString().c_str() );
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;
    }

    setUsageTemplate( sTemplate, uCount );

    rv = pP11->FindObjectsInit( slot_info_.getSessionHandle(), sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjects( slot_info_.getSessionHandle(), hObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = pP11->FindObjectsFinal( slot_info_.getSessionHandle() );
    if( rv != CKR_OK ) goto end;


    for( int i = 0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        long nKeyType = -1;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_KEY_TYPE, &binKeyType );
        if( rv != CKR_OK ) goto end;

        rv = pP11->GetAttributeValue2( slot_info_.getSessionHandle(), hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        if( binID.nLen < 1 ) continue;

        JS_BIN_string( &binLabel, &pLabel );
        memcpy( &nKeyType, binKeyType.pVal, binKeyType.nLen );

        mSecretTable->insertRow(0);
        mSecretTable->setRowHeight(0, 10);
        QTableWidgetItem *item = new QTableWidgetItem( pLabel );
        item->setIcon(QIcon(":/images/key.png"));

        QString strData = QString( "SECRET:%1:%2:%3" ).arg( hObjects[i] ).arg( getHexString( &binID )).arg( nKeyType );
        item->setData(Qt::UserRole, strData);

        mSecretTable->setItem(0, 0, item);
        mSecretTable->setItem(0,1, new QTableWidgetItem( QString( "%1").arg( JS_PKCS11_GetCKKName( nKeyType ))) );
        mSecretTable->setItem(0, 2, new QTableWidgetItem( QString("%1").arg( hObjects[i] )));
        mSecretTable->setItem(0, 3, new QTableWidgetItem( QString("%1").arg( getHexString( &binID ))));

        if( pLabel )
        {
            JS_free( pLabel );
            pLabel = NULL;
        }
    }

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binKeyType );

    return;
}

void HsmManDlg::clickCertObjectView()
{
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem *item = mCertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 2 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( hObj );
    objectView.exec();
}

void HsmManDlg::clickCertView()
{
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem *item = mCertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    int ret = 0;
    BIN binCert = {0,0};
    CertInfoDlg certInfoDlg;

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), hObj, CKA_VALUE, &binCert );
    if( ret != CKR_OK )
    {
        manApplet->warningBox( tr( "failed to get certificate: %1").arg(ret), this );
        goto end;
    }

    certInfoDlg.setCertVal( getHexString( &binCert ));
    certInfoDlg.exec();

end :
    JS_BIN_reset( &binCert );
}

void HsmManDlg::clickCertDelete()
{
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem *item = mCertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the ceritificate?" ), this, false );
    if( bVal == false ) return;

    int rv = manApplet->cryptokiAPI()->DestroyObject( slot_info_.getSessionHandle(), hObj );
    if( rv == CKR_OK )
    {
        manApplet->messageBox( tr("The certificate is deleted"), this );
        loadCertList();
    }
}

void HsmManDlg::clickCertExport()
{
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem *item = mCertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    JCertInfo sCertInfo;
    ExportDlg exportDlg;
    BIN binCert = {0,0};

    int ret = manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), hObj, CKA_VALUE, &binCert );
    if( ret != CKR_OK )
    {
        manApplet->warningBox( tr( "failed to get certificate: %1").arg(ret), this );
        goto end;
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "Invalid certificate" ), this );
        JS_BIN_reset( &binCert );
        return;
    }

    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setCert( &binCert );
    exportDlg.exec();

end :
    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void HsmManDlg::clickCertDeleteKeyPair()
{
    int rv = 0;
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem *item = mCertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);
    BIN binID = {0,0};
    long hPri = -1;
    long hPub = -1;

    bool bVal = manApplet->yesOrCancelBox( tr( "Do you want to delete a certificate and key pair with the same CKA_ID?" ), this, false );
    if( bVal == false ) return;

    JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    if( binID.nLen > 0 )
    {
        hPri = manApplet->cryptokiAPI()->getHandle( slot_info_.getSessionHandle(), CKO_PRIVATE_KEY, &binID );
        if( hPri < 0 )
        {
            manApplet->warningBox( tr( "fail to get private handle: %1").arg( hPri ), this );
            goto end;
        }

        hPub = manApplet->cryptokiAPI()->getHandle( slot_info_.getSessionHandle(), CKO_PUBLIC_KEY, &binID );
        if( hPub < 0 )
        {
            manApplet->warningBox( tr( "fail to get public handle: %1").arg( hPri ), this );
            goto end;
        }
    }

    rv = manApplet->cryptokiAPI()->DestroyObject( slot_info_.getSessionHandle(), hPri );
    if( rv != CKR_OK )
    {
        manApplet->elog( QString( "fail to delete private key[H:%1]").arg(hPri));
    }

    rv = manApplet->cryptokiAPI()->DestroyObject( slot_info_.getSessionHandle(), hPub );
    if( rv != CKR_OK )
    {
        manApplet->elog( QString( "fail to delete public key[H:%1]").arg(hPub));
    }

    rv = manApplet->cryptokiAPI()->DestroyObject( slot_info_.getSessionHandle(), hObj );
    if( rv == CKR_OK )
    {
        manApplet->messageBox( tr("The certificate is deleted"), this );
        loadCertList();
    }

end :
    JS_BIN_reset( &binID );
}

void HsmManDlg::clickPublicObjectView()
{
    QModelIndex idx = mPublicTable->currentIndex();
    QTableWidgetItem *item = mPublicTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 2 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( hObj );
    objectView.exec();
}

void HsmManDlg::clickPublicView()
{
    QModelIndex idx = mPublicTable->currentIndex();
    QTableWidgetItem *item = mPublicTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);
    int nKeyType = listData.at(3).toInt();

    PriKeyInfoDlg priKeyInfo;
    priKeyInfo.setPublicKey( slot_info_.getSessionHandle(), hObj );
    priKeyInfo.exec(); 
}

void HsmManDlg::clickPublicDelete()
{
    QModelIndex idx = mPublicTable->currentIndex();
    QTableWidgetItem *item = mPublicTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the public key" ), this, false );
    if( bVal == false ) return;

    int rv = manApplet->cryptokiAPI()->DestroyObject( slot_info_.getSessionHandle(), hObj );
    if( rv == CKR_OK )
    {
        manApplet->messageBox( tr("The public key is deleted"), this );
        loadPublicList();
    }
}

void HsmManDlg::clickPublicExport()
{
    QModelIndex idx = mPublicTable->currentIndex();
    QTableWidgetItem *item = mPublicTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    BIN binPubKey = {0,0};
    ExportDlg exportDlg;

    int ret = getPublicKey( manApplet->cryptokiAPI(), slot_info_.getSessionHandle(), hObj, &binPubKey );
    if( ret !=  0 )
    {
        manApplet->warningBox( tr( "failed to get public key: %1").arg(ret), this );
        goto end;
    }


    exportDlg.setPublicKey( &binPubKey );
    exportDlg.setName( QString( "PublicKey_%1" ).arg( hObj ));
    exportDlg.exec();


end :
    JS_BIN_reset( &binPubKey );
}

void HsmManDlg::clickPublicVerify()
{
    QModelIndex idx = mPublicTable->currentIndex();
    QTableWidgetItem *item = mPublicTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    VerifyDlg verifyDlg;
    verifyDlg.setSlotIndex( slot_index_ );
    verifyDlg.mKeyTypeCombo->setCurrentText( "PUBLIC" );
    verifyDlg.mObjectText->setText( QString("%1").arg( hObj));
    verifyDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    verifyDlg.exec();
}

void HsmManDlg::clickPublicEncrypt()
{
    QModelIndex idx = mPublicTable->currentIndex();
    QTableWidgetItem *item = mPublicTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    EncryptDlg encDlg;
    encDlg.setSlotIndex( slot_index_ );
    encDlg.mKeyTypeCombo->setCurrentText( "PUBLIC" );
    encDlg.mObjectText->setText( QString("%1").arg( hObj));
    encDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    encDlg.exec();
}

void HsmManDlg::clickPrivateObjectView()
{
    QModelIndex idx = mPrivateTable->currentIndex();
    QTableWidgetItem *item = mPrivateTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 2 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( hObj );
    objectView.exec();
}

void HsmManDlg::clickPrivateView()
{
    QModelIndex idx = mPrivateTable->currentIndex();
    QTableWidgetItem *item = mPrivateTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);


    PriKeyInfoDlg priKeyInfo;
    priKeyInfo.setPrivateKey( slot_info_.getSessionHandle(), hObj );
    priKeyInfo.exec(); 
}

void HsmManDlg::clickPrivateDelete()
{
    QModelIndex idx = mPrivateTable->currentIndex();
    QTableWidgetItem *item = mPrivateTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the private key" ), this, false );
    if( bVal == false ) return;

    int rv = manApplet->cryptokiAPI()->DestroyObject( slot_info_.getSessionHandle(), hObj );
    if( rv == CKR_OK )
    {
        manApplet->messageBox( tr("The private key is deleted"), this );
        loadPrivateList();
    }
}

void HsmManDlg::clickPrivateExport()
{
    QModelIndex idx = mPrivateTable->currentIndex();
    QTableWidgetItem *item = mPrivateTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    BIN binPriKey = {0,0};
    ExportDlg exportDlg;

    int ret = getPrivateKey( manApplet->cryptokiAPI(), slot_info_.getSessionHandle(), hObj, &binPriKey );
    if( ret !=  0 )
    {
        manApplet->warningBox( tr( "failed to get private key: %1").arg(ret), this );
        goto end;
    }

    exportDlg.setName( QString( "PrivateKey_%1" ).arg( hObj));
    exportDlg.setPrivateKey( &binPriKey );
    exportDlg.exec();


end :
    JS_BIN_reset( &binPriKey );
}

void HsmManDlg::clickPrivateSign()
{
    QModelIndex idx = mPrivateTable->currentIndex();
    QTableWidgetItem *item = mPrivateTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    SignDlg signDlg;
    signDlg.setSlotIndex( slot_index_ );
    signDlg.mKeyTypeCombo->setCurrentText( "PRIVATE" );
    signDlg.mObjectText->setText( QString("%1").arg( hObj));
    signDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    signDlg.exec();
}

void HsmManDlg::clickPrivateDecrypt()
{
    QModelIndex idx = mPrivateTable->currentIndex();
    QTableWidgetItem *item = mPrivateTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    DecryptDlg decDlg;
    decDlg.setSlotIndex( slot_index_ );
    decDlg.mKeyTypeCombo->setCurrentText( "PRIVATE" );
    decDlg.mObjectText->setText( QString("%1").arg( hObj));
    decDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    decDlg.exec();
}

void HsmManDlg::clickSecretObjectView()
{
    QModelIndex idx = mSecretTable->currentIndex();
    QTableWidgetItem *item = mSecretTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 2 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( hObj );
    objectView.exec();
}

void HsmManDlg::clickSecretView()
{
    QModelIndex idx = mSecretTable->currentIndex();
    QTableWidgetItem *item = mSecretTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    SecretInfoDlg secretInfo;
    secretInfo.setHandle( slot_info_.getSessionHandle(), hObj );
    secretInfo.exec();
}

void HsmManDlg::clickSecretDelete()
{
    QModelIndex idx = mSecretTable->currentIndex();
    QTableWidgetItem *item = mSecretTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the secret key" ), this, false );
    if( bVal == false ) return;

    int rv = manApplet->cryptokiAPI()->DestroyObject( slot_info_.getSessionHandle(), hObj );
    if( rv == CKR_OK )
    {
        manApplet->messageBox( tr("The secret key is deleted"), this );
        loadSecretList();
    }
}

void HsmManDlg::clickSecretEncrypt()
{
    QModelIndex idx = mSecretTable->currentIndex();
    QTableWidgetItem *item = mSecretTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    EncryptDlg encDlg;
    encDlg.setSlotIndex( slot_index_ );
    encDlg.mKeyTypeCombo->setCurrentText( "SECRET" );
    encDlg.mObjectText->setText( QString("%1").arg( hObj));
    encDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    encDlg.exec();
}

void HsmManDlg::clickSecretDecrypt()
{
    QModelIndex idx = mSecretTable->currentIndex();
    QTableWidgetItem *item = mSecretTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    DecryptDlg decDlg;
    decDlg.setSlotIndex( slot_index_ );
    decDlg.mKeyTypeCombo->setCurrentText( "SECRET" );
    decDlg.mObjectText->setText( QString("%1").arg( hObj));
    decDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    decDlg.exec();
}

void HsmManDlg::clickSecretSign()
{
    QModelIndex idx = mSecretTable->currentIndex();
    QTableWidgetItem *item = mSecretTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    SignDlg signDlg;
    signDlg.setSlotIndex( slot_index_ );
    signDlg.mKeyTypeCombo->setCurrentText( "SECRET" );
    signDlg.mObjectText->setText( QString("%1").arg( hObj));
    signDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    signDlg.exec();
}

void HsmManDlg::clickSecretVerify()
{
    QModelIndex idx = mSecretTable->currentIndex();
    QTableWidgetItem *item = mSecretTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    QString strType = listData.at(0);
    long hObj = listData.at(1).toLong();
    QString strID = listData.at(2);

    VerifyDlg verifyDlg;
    verifyDlg.setSlotIndex( slot_index_ );
    verifyDlg.mKeyTypeCombo->setCurrentText( "SECRET" );
    verifyDlg.mObjectText->setText( QString("%1").arg( hObj));
    verifyDlg.mLabelText->setText( manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj ));
    verifyDlg.exec();
}

void HsmManDlg::clickOK()
{
    str_data_.clear();

    QModelIndex idx;
    QTableWidgetItem *item = NULL;
    int nTabIdx = mTabWidget->currentIndex();

    if( nTabIdx == TAB_CERT_IDX )
    {
        idx = mCertTable->currentIndex();
        item = mCertTable->item( idx.row(), 0 );
    }
    else if( nTabIdx == TAB_PUBLIC_IDX )
    {
        idx = mPublicTable->currentIndex();
        item = mPublicTable->item( idx.row(), 0 );
    }
    else if( nTabIdx == TAB_PRIVATE_IDX )
    {
        idx = mPrivateTable->currentIndex();
        item = mPrivateTable->item( idx.row(), 0 );
    }
    else if( nTabIdx == TAB_SECRET_IDX )
    {
        idx = mSecretTable->currentIndex();
        item = mSecretTable->item( idx.row(), 0 );
    }

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    QString strData = item->data(Qt::UserRole).toString();
    QStringList listData = strData.split(":");
    if( listData.size() < 3 ) return;

    str_data_ = strData;

    accept();
}
