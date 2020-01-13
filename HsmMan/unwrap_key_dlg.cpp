#include <QFileDialog>

#include "unwrap_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"

static QStringList sUnwrapMechList = {
    "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP",
    "CKM_DES3_ECB", "CKM_DES3_CBC", "CKM_DES3_CBC_PAD",
    "CKM_AES_ECB", "CKM_AES_CBC", "CKM_AES_CBC_PAD"
};


static QStringList sClassList = {
    "CKO_PRIVATE_KEY", "CKO_SECRET_KEY"
};


static QStringList sTypeList = {
    "CKK_RSA", "CKK_DSA", "CKK_ECDSA", "CKK_EC",
    "CKK_DES", "CKK_DES3", "CKK_AES"
};

UnwrapKeyDlg::UnwrapKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
}

UnwrapKeyDlg::~UnwrapKeyDlg()
{

}

void UnwrapKeyDlg::initUI()
{
    mUnwrapMechCombo->addItems(sUnwrapMechList);
    mClassCombo->addItems(sClassList);
    mTypeCombo->addItems(sTypeList);

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mUnwrapLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(unwrapLabelChanged(int)));
    connect( mFindBtn, SIGNAL(clicked(bool)), this, SLOT(clickFind()));

    /* need to check crashing */

}

void UnwrapKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void UnwrapKeyDlg::showEvent(QShowEvent* event )
{
    initialize();
    setUnwrapLabelList();
}

void UnwrapKeyDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);
}

void UnwrapKeyDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    int rv = -1;

    QString strWrapPath = mWrapKeyPathText->text();

    if( strWrapPath.isEmpty() )
    {
        QMessageBox::warning( this, "UnwrapKey", "You have to select wrapped file." );
        return;
    }


    CK_MECHANISM sMech;
    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE uObj = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_OBJECT_CLASS objClass = 0;
    CK_KEY_TYPE keyType = 0;
    CK_OBJECT_HANDLE hUnwrappingKey = -1;

    hUnwrappingKey = mUnwrapObjectText->text().toLong();

    BIN binWrappedKey = {0,0};
    JS_BIN_fileRead( strWrapPath.toStdString().c_str(), &binWrappedKey );

    sMech.mechanism = JS_PKCS11_GetCKMType( mUnwrapMechCombo->currentText().toStdString().c_str());

    BIN binParam = {0,0};
    QString strParam = mUnwrapParamText->text();

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    objClass = JS_PKCS11_GetCKOType( mClassCombo->currentText().toStdString().c_str());
    keyType = JS_PKCS11_GetCKKType( mTypeCombo->currentText().toStdString().c_str());

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mLabelText->text();
    BIN binLabel = {0,0};

    if( strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    if( mDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        sTemplate[uCount].pValue = ( mDecryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mEncryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ENCRYPT;
        sTemplate[uCount].pValue = ( mEncryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = ( mModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = ( mSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        sTemplate[uCount].pValue = ( mSignCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mUnwrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_UNWRAP;
        sTemplate[uCount].pValue = ( mUnwrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mVerifyCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY;
        sTemplate[uCount].pValue = ( mVerifyCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        sTemplate[uCount].pValue = ( mWrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }


    rv = JS_PKCS11_UnwrapKey( p11_ctx, hSession, &sMech, hUnwrappingKey,
                              binWrappedKey.pVal, binWrappedKey.nLen, sTemplate, uCount, &uObj );

    if( rv != CKR_OK )
    {
        return;
    }

    QString strObject = QString("%1").arg( uObj );
    mObjectText->setText(strObject);

    QDialog::accept();
}

void UnwrapKeyDlg::unwrapLabelChanged(int index)
{
    QVariant objVal = mUnwrapLabelCombo->itemData(index);

    QString strObject = QString("%1").arg( objVal.toInt() );


    mUnwrapObjectText->setText( strObject );
}

void UnwrapKeyDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("QFileDialog::getOpenFileName()"),
                                                     "D:/test",
                                                     tr("DLL Files (*.dll);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mWrapKeyPathText->setText( fileName );
}

void UnwrapKeyDlg::setUnwrapLabelList()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    objClass = CKO_SECRET_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, uCnt );
    JS_PKCS11_FindObjects( p11_ctx, hSession, sObjects, uMaxObjCnt, &uObjCnt );
    JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );


    mUnwrapLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, sObjects[i], CKA_LABEL, &binLabel );
        JS_BIN_string( &binLabel, &pLabel );

       mUnwrapLabelCombo->addItem( pLabel, objVal );
       JS_BIN_reset(&binLabel );
       if( pLabel ) JS_free(pLabel);
    }

    uCnt = 0;
    uObjCnt = 0;
    objClass = CKO_PUBLIC_KEY;
    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, uCnt );
    JS_PKCS11_FindObjects( p11_ctx, hSession, sObjects, uMaxObjCnt, &uObjCnt );
    JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, sObjects[i], CKA_LABEL, &binLabel );
        JS_BIN_string( &binLabel, &pLabel );

       mUnwrapLabelCombo->addItem( pLabel, objVal );
       JS_BIN_reset(&binLabel );
       if( pLabel ) JS_free(pLabel);
    }

    int iKeyCnt = mUnwrapLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mUnwrapLabelCombo->itemData(0);

        QString strObject = QString("%1").arg( objVal.toInt() );
        mUnwrapObjectText->setText(strObject);
    }
}
