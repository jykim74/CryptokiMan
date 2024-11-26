#include "secret_info_dlg.h"
#include "man_applet.h"
#include "settings_mgr.h"
#include "p11_work.h"
#include "cryptoki_api.h"
#include "common.h"

SecretInfoDlg::SecretInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    handle_ = -1;
    session_ = -1;

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mKeyText, SIGNAL(textChanged(QString)), this, SLOT(changeKey()));
    connect( mIDText, SIGNAL(textChanged(QString)), this, SLOT(changeID()));
}

SecretInfoDlg::~SecretInfoDlg()
{

}

void SecretInfoDlg::initialize()
{
    int rv = 0;
    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binVal = {0,0};
    BIN binKeyType = {0,0};
    BIN binKeyLen = {0,0};
    int nKeyType = -1;
    int nKeyLen = -1;

    char *pLabel = NULL;
    QString strVal;

    CryptokiAPI *pP11 = manApplet->cryptokiAPI();

    if( session_ < 0 || handle_ < 0 ) return;

    rv = pP11->GetAttributeValue2( session_, handle_, CKA_LABEL, &binLabel );
    if( rv == CKR_OK ) JS_BIN_string( &binLabel, &pLabel );

    rv = pP11->GetAttributeValue2( session_, handle_, CKA_ID, &binID );

    rv = pP11->GetAttributeValue2( session_, handle_, CKA_KEY_TYPE, &binKeyType );
    if( rv == CKR_OK ) memcpy( &nKeyType, binKeyType.pVal, binKeyType.nLen );

    rv = pP11->GetAttributeValue2( session_, handle_, CKA_VALUE_LEN, &binKeyLen );
    if( rv == CKR_OK ) memcpy( &nKeyLen, binKeyLen.pVal, binKeyLen.nLen );

    rv = pP11->GetAttributeValue2( session_, handle_, CKA_VALUE, &binVal );
    if( rv == CKR_OK )
    {
        mKeyTypeCombo->addItem( "Hex" );
        strVal = getHexString( &binVal );
    }
    else
    {
        mKeyTypeCombo->addItem( "String" );
        strVal = QString( "%1[0x%2]" ).arg( JS_PKCS11_GetErrorMsg( rv )).arg(rv,0,16);
    }

    mIDTypeCombo->addItem( "Hex" );

    mLabelText->setText( pLabel );
    mHandleText->setText( QString("%1").arg( handle_ ));
    mKeyText->setText( strVal );
    mIDText->setText( getHexString( &binID ));
    mKeyTypeText->setText( JS_PKCS11_GetCKKName( nKeyType ));
    mKeyLengthText->setText( QString("%1").arg( nKeyLen ));

end :
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binKeyType );
    JS_BIN_reset( &binKeyLen );
    if( pLabel ) JS_free( pLabel );
}

void SecretInfoDlg::setHandle( long hSession, long hObj )
{
    session_ = hSession;
    handle_ = hObj;
}

void SecretInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void SecretInfoDlg::changeKey()
{
    QString strKey = mKeyText->text();
    QString strLen = getDataLenString( mKeyTypeCombo->currentText(), strKey );
    mKeyLenText->setText( strLen );
}

void SecretInfoDlg::changeID()
{
    QString strID = mIDText->text();
    QString strLen = getDataLenString( mIDTypeCombo->currentText(), strID );
    mIDLenText->setText( strLen );
}
