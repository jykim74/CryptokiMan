#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>
#include <QList>

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
    session_ = -1;

    setupUi(this);
    initUI();

    memset( &csr_, 0x00, sizeof(BIN));

    connect( mPriLabelCombo, SIGNAL(currentIndexChanged(int)), SLOT(changePriLabel(int)));
    connect( mPubLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changePubLabel(int)));

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));

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

void MakeCSRDlg::setSelectedSlot(int index)
{
    slotChanged( index );
    getPriCombo();
}

void MakeCSRDlg::setPriObject( CK_OBJECT_HANDLE hPriObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    manApplet->cryptokiAPI()->GetAttributeValue2( session_, hPriObj, CKA_LABEL, &binVal );
    JS_BIN_string( &binVal, &pLabel );
    JS_BIN_reset( &binVal );

    mPriLabelCombo->setCurrentText( pLabel );
    mPriObjectText->setText( QString("%1").arg( hPriObj ));

    if( pLabel ) JS_free( pLabel );
}

void MakeCSRDlg::setSession( CK_SESSION_HANDLE hSession )
{
    session_ = hSession;
}

void MakeCSRDlg::initUI()
{

}

void MakeCSRDlg::initialize()
{
    SettingsMgr *setMgr = manApplet->settingsMgr();

    mSignHashCombo->addItems( kHashList );
    mSignHashCombo->setCurrentText( "SHA256" );
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

    QString strDN;

    if( strEmailAddress.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "emailAddress=%1").arg(strEmailAddress);
    }

    if( strCN.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "CN=%1").arg( strCN );
    }

    if( strO.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "O=%1").arg( strO );
    }

    if( strOU.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "OU=%1").arg( strOU );
    }

    if( strL.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "L=%1").arg( strL );
    }

    if( strST.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "ST=%1").arg( strST );
    }

    if( strC.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "C=%1" ).arg( strC );
    }

    return strDN;
}

void MakeCSRDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    session_ = slotInfo.getSessionHandle();
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
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

void MakeCSRDlg::clickOK()
{
    int ret = 0;
    QString strHash = mSignHashCombo->currentText();
    QString strDN = getDN();

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

    ret = getPublicKey( manApplet->cryptokiAPI(), session_, hPub, &binPub );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to get public key: %1" ).arg( ret ), this );
        return;
    }

    ret = JS_PKI_makeCSRByP11Handle(
        strHash.toStdString().c_str(),
        strDN.toStdString().c_str(),
        NULL,
        NULL,
        hPri,
        &binPub,
        NULL,
        manApplet->cryptokiAPI()->getCTX(),
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
        return QDialog::reject();
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


    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return rv;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return rv;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return rv;

    mPriLabelCombo->clear();
    mPriObjectText->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

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

    rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, hPriObj, CKA_KEY_TYPE, &binType );
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


    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK )
    {
        JS_BIN_reset( &binType );
        return rv;
    }

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK )
    {
        JS_BIN_reset( &binType );
        return rv;
    }

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
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

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

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
