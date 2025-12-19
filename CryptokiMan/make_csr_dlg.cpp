#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>
#include <QList>
#include <QAction>
#include <QMenu>

#include "make_csr_dlg.h"
#include "common.h"
#include "slot_info.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "p11_work.h"
#include "js_error.h"
#include "object_view_dlg.h"

const QStringList kRDNList = {
    "emailAddress", "CN", "OU", "O",
    "L", "ST", "C"
};


static QStringList kHashList = {
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SM3"
};

MakeCSRDlg::MakeCSRDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &csr_, 0x00, sizeof(BIN));

    connect( mRDNTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));

    connect( mPriLabelCombo, SIGNAL(currentIndexChanged(int)), SLOT(changePriLabel(int)));
    connect( mPubLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changePubLabel(int)));

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));

    connect( mPriViewBtn, SIGNAL(clicked()), this, SLOT(viewPriObject()));
    connect( mPubViewBtn, SIGNAL(clicked()), this, SLOT(viewPubObject()));

    connect( mEMAILADDRESSText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mCNText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mOText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mOUText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mLText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mSTText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mCText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));

    connect( mRDNAddBtn, SIGNAL(clicked()), this, SLOT(clickRDNAdd()));

    initialize();
    mOKBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeCSRDlg::~MakeCSRDlg()
{
    JS_BIN_reset( &csr_ );
}

void MakeCSRDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotInfoText->setText( getSlotInfo( slot_info_) );
        mSlotBtn->setIcon( getSlotIcon( slot_info_ ) );
    }

    getPriCombo();
}

void MakeCSRDlg::setPriObject( CK_OBJECT_HANDLE hPriObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), hPriObj, CKA_LABEL, &binVal );
    JS_BIN_string( &binVal, &pLabel );
    JS_BIN_reset( &binVal );

    mPriLabelCombo->setCurrentText( pLabel );
    mPriObjectText->setText( QString("%1").arg( hPriObj ));

    if( pLabel ) JS_free( pLabel );
}

void MakeCSRDlg::setSession( CK_SESSION_HANDLE hSession )
{
    slot_info_.setSessionHandle( hSession );
}

void MakeCSRDlg::initUI()
{
    mRDNNameCombo->setEditable(true);
    mRDNNameCombo->addItems( kRDNList );

    mEMAILADDRESSText->setPlaceholderText( "Email" );
    mCNText->setPlaceholderText( "Common Name" );
    mOUText->setPlaceholderText( "Organization Unit" );
    mOText->setPlaceholderText( "Organization" );
    mLText->setPlaceholderText( "Locality" );
    mSTText->setPlaceholderText( "State/Province" );
    mCText->setPlaceholderText( "Country" );


    QStringList sBaseLabels = { tr("Name"), tr("Value") };

    mRDNTable->clear();
    mRDNTable->horizontalHeader()->setStretchLastSection(true);
    mRDNTable->setColumnCount(sBaseLabels.size());
    mRDNTable->setHorizontalHeaderLabels( sBaseLabels );
    mRDNTable->verticalHeader()->setVisible(false);
    mRDNTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRDNTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mRDNTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRDNTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void MakeCSRDlg::initialize()
{
    SettingsMgr *setMgr = manApplet->settingsMgr();

    mSignHashCombo->addItems( kHashList );
    mSignHashCombo->setCurrentText( "SHA256" );

    mCNText->setFocus();
}

const QString MakeCSRDlg::getCSRHex()
{
    return getHexString( &csr_ );
}

const QString MakeCSRDlg::getDN()
{
    QString strEmailAddress = mEMAILADDRESSText->text();
    QString strCN = mCNText->text();
    QString strO = mOText->text();
    QString strOU = mOUText->text();
    QString strL = mLText->text();
    QString strST = mSTText->text();
    QString strC = mCText->text();


    QString strRDN_Email;
    QString strRDN_CN;
    QString strRDN_OU;
    QString strRDN_O;
    QString strRDN_L;
    QString strRDN_ST;
    QString strRDN_C;
    QString strRDN_More;


    QString strDN;

    if( strEmailAddress.length() > 0 )
    {
        strRDN_Email = QString( "emailAddress=%1").arg(strEmailAddress);
    }

    if( strCN.length() > 0 )
    {
        strRDN_CN = QString( "CN=%1").arg( strCN );
    }

    if( strOU.length() > 0 )
    {
        strRDN_OU = QString( "OU=%1").arg( strOU );
    }

    if( strO.length() > 0 )
    {
        strRDN_O = QString( "O=%1").arg( strO );
    }

    if( strL.length() > 0 )
    {
        strRDN_L = QString( "L=%1").arg( strL );
    }

    if( strST.length() > 0 )
    {
        strRDN_ST = QString( "ST=%1").arg( strST );
    }

    if( strC.length() > 0 )
    {
        strRDN_C = QString( "C=%1" ).arg( strC );
    }

    int nCount = mRDNTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        QTableWidgetItem *item0 = mRDNTable->item(i, 0);
        QTableWidgetItem *item1 = mRDNTable->item(i, 1);

        QString strName = item0->text();
        QString strValue = item1->text();

        if( strName == "emailAddress" )
        {
            if( strRDN_Email.length() > 0 ) strRDN_Email += ",";
            strRDN_Email += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "CN" )
        {
            if( strRDN_CN.length() > 0 ) strRDN_CN += ",";
            strRDN_CN += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "OU" )
        {
            if( strRDN_OU.length() > 0 ) strRDN_OU += ",";
            strRDN_OU += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "O" )
        {
            if( strRDN_O.length() > 0 ) strRDN_O += ",";
            strRDN_O += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "L" )
        {
            if( strRDN_L.length() > 0 ) strRDN_L += ",";
            strRDN_L += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "ST" )
        {
            if( strRDN_ST.length() > 0 ) strRDN_ST += ",";
            strRDN_ST += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "C" )
        {
            if( strRDN_C.length() > 0 ) strRDN_C += ",";
            strRDN_C += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else
        {
            if( strRDN_More.length() > 0 ) strRDN_More += ",";
            strRDN_More += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
    }

    if( strRDN_More.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_More;
    }

    if( strRDN_Email.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_Email;
    }

    if( strRDN_CN.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_CN;
    }

    if( strRDN_OU.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_OU;
    }

    if( strRDN_O.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_O;
    }

    if( strRDN_L.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_L;
    }

    if( strRDN_ST.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_ST;
    }

    if( strRDN_C.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_C;
    }

    return strDN;
}

void MakeCSRDlg::clickClear()
{
    mEMAILADDRESSText->clear();
    mCNText->clear();
    mOText->clear();
    mOUText->clear();
    mLText->clear();
    mSTText->clear();
    mCText->clear();
}

void MakeCSRDlg::changeDN()
{
    QString strDN = getDN();
    mDNText->setText( strDN );
}

void MakeCSRDlg::clickRDNAdd()
{
    QString strName = mRDNNameCombo->currentText();
    QString strValue = mRDNValueText->text();

    if( strName.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a name" ), this );
        mRDNNameCombo->setFocus();
        return;
    }

    if( strValue.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a value" ), this );
        mRDNValueText->setFocus();
        return;
    }

    mRDNTable->insertRow(0);
    mRDNTable->setRowHeight(0, 10);
    mRDNTable->setItem( 0, 0, new QTableWidgetItem( strName ));
    mRDNTable->setItem( 0, 1, new QTableWidgetItem( strValue ));

    mRDNValueText->clear();
    changeDN();
}

void MakeCSRDlg::deleteRDN()
{
    QModelIndex idx = mRDNTable->currentIndex();
    QTableWidgetItem* item = mRDNTable->item( idx.row(), 0 );

    if( item )
    {
        mRDNTable->removeRow( idx.row() );
        changeDN();
    }
}

void MakeCSRDlg::viewPriObject()
{
    long hObj = mPriObjectText->text().toLong();

    if( hObj <= 0 )
    {
        manApplet->warningBox( tr( "There is no object" ), this );
        return;
    }

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( hObj );
    objectView.exec();
}

void MakeCSRDlg::viewPubObject()
{
    long hObj = mPubObjectText->text().toLong();

    if( hObj <= 0 )
    {
        manApplet->warningBox( tr( "There is no object" ), this );
        return;
    }

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( hObj );
    objectView.exec();
}

void MakeCSRDlg::changePriLabel( int index )
{
    QVariant objVal = mPriLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mPriObjectText->setText( strHandle );

    getPubCombo();
}

void MakeCSRDlg::changePubLabel( int index )
{
    QVariant objVal = mPubLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mPubObjectText->setText( strHandle );
}


void MakeCSRDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction* deleteAct = new QAction( tr( "Delete" ), this );

    connect( deleteAct, SIGNAL(triggered()), this, SLOT(deleteRDN()));

    menu->addAction( deleteAct );
    menu->popup( mRDNTable->viewport()->mapToGlobal(pos));
}

void MakeCSRDlg::clickOK()
{
    int ret = 0;
    QString strHash = mSignHashCombo->currentText();
    QString strDN = getDN();
    JP11_CTX *pCTX = manApplet->cryptokiAPI()->getCTX();

    BIN binPub = {0,0};
    JS_BIN_reset( &csr_ );

    CK_OBJECT_HANDLE hPub = mPubObjectText->text().toLong();
    CK_OBJECT_HANDLE hPri = mPriObjectText->text().toLong();

    if( strDN.length() < 1 )
    {
        manApplet->warningBox( tr( "Insert DN"), this );
        mCNText->setFocus();
        return;
    }

    ret = getPublicKey( manApplet->cryptokiAPI(), slot_info_.getSessionHandle(), hPub, &binPub );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to get public key: %1" ).arg( ret ), this );
        return;
    }

    pCTX->hSession = slot_info_.getSessionHandle();

    ret = JS_PKI_makeCSRByP11Handle(
        strHash.toStdString().c_str(),
        strDN.toStdString().c_str(),
        mChallengeText->text().length() > 0 ? mChallengeText->text().toStdString().c_str() : NULL,
        mUnstructuredText->text().length() > 0 ? mUnstructuredText->text().toStdString().c_str() : NULL,
        hPri,
        &binPub,
        NULL,
        pCTX,
        &csr_ );


    JS_BIN_reset( &binPub );

    if( ret == 0 )
    {
        ret = JS_PKI_verifyCSR( &csr_ );
        if( ret != JSR_VALID )
        {
            manApplet->warnLog( tr( "fail to verify CSR: %1").arg( ret ), this );
            return;
        }

        return QDialog::accept();
    }
    else
    {
        manApplet->warnLog( tr( "fail to make CSR: %1").arg( ret ), this);
        return;
    }
}

int MakeCSRDlg::getPriCombo()
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    objClass = CKO_PRIVATE_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_SIGN;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;


    rv = manApplet->cryptokiAPI()->FindObjectsInit( slot_info_.getSessionHandle(), sTemplate, uCnt );
    if( rv != CKR_OK ) return rv;

    rv = manApplet->cryptokiAPI()->FindObjects( slot_info_.getSessionHandle(), sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return rv;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( slot_info_.getSessionHandle() );
    if( rv != CKR_OK ) return rv;

    mPriLabelCombo->clear();
    mPriObjectText->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), sObjects[i], CKA_LABEL, &binLabel );

        QVariant objVal = QVariant((int)sObjects[i]);
        JS_BIN_string( &binLabel, &pStr );
        mPriLabelCombo->addItem( pStr, objVal );
        if( pStr ) JS_free( pStr );
        JS_BIN_reset(&binLabel);
    }

    if( uObjCnt > 0 )
    {
        QString strHandle = QString("%1").arg( sObjects[0] );
        mPriObjectText->setText( strHandle );
    }

    return 0;
}

int MakeCSRDlg::getPubCombo()
{
    int rv = -1;

    CK_OBJECT_HANDLE hPriObj = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    BIN binType = {0,0};

    QString strPriObject = mPriObjectText->text();
    if( strPriObject.length() < 1 ) return JSR_ERR;

    hPriObj = strPriObject.toLong();

    rv = manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), hPriObj, CKA_KEY_TYPE, &binType );
    if( rv != CKR_OK ) return JSR_ERR2;


    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_VERIFY;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    sTemplate[uCnt].type = CKA_KEY_TYPE;
    sTemplate[uCnt].pValue = binType.pVal;
    sTemplate[uCnt].ulValueLen = binType.nLen;
    uCnt++;


    rv = manApplet->cryptokiAPI()->FindObjectsInit( slot_info_.getSessionHandle(), sTemplate, uCnt );
    if( rv != CKR_OK )
    {
        JS_BIN_reset( &binType );
        return rv;
    }

    rv = manApplet->cryptokiAPI()->FindObjects( slot_info_.getSessionHandle(), sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK )
    {
        JS_BIN_reset( &binType );
        return rv;
    }

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( slot_info_.getSessionHandle() );
    if( rv != CKR_OK )
    {
        JS_BIN_reset( &binType );
        return rv;
    }

    JS_BIN_reset( &binType );

    mPubLabelCombo->clear();
    mPubObjectText->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), sObjects[i], CKA_LABEL, &binLabel );

        QVariant objVal = QVariant((int)sObjects[i]);
        JS_BIN_string( &binLabel, &pStr );
        mPubLabelCombo->addItem( pStr, objVal );
        if( pStr ) JS_free( pStr );
        JS_BIN_reset(&binLabel);
    }

    if( uObjCnt > 0 )
    {
        QString strHandle = QString("%1").arg( sObjects[0] );
        mPubObjectText->setText( strHandle );
    }

    return 0;
}
