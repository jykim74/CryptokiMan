#include "common.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"

#include "edit_attribute_list_dlg.h"

static QStringList sFalseTrue = { "false", "true" };

EditAttributeListDlg::EditAttributeListDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    object_type_ = -1;
    object_id_ = -1;
    session_ = -1;

    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mObjectTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mLabelText, SIGNAL(textChanged(QString)), this, SLOT(changeLabel(QString)));
    connect( mIDText, SIGNAL(textChanged(QString)), this, SLOT(changeID(QString)));
    connect( mApplicationText, SIGNAL(textChanged(QString)), this, SLOT(changeApplication(QString)));
    connect( mObjectIDText, SIGNAL(textChanged(QString)), this, SLOT(changeObjectID(QString)));

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect( mGetAttributeBtn, SIGNAL(clicked(bool)), this, SLOT(clickGetAttribute()));
    connect( mSetAttributeBtn, SIGNAL(clicked(bool)), this, SLOT(clickSetAttribute()));

    initialize();
}

EditAttributeListDlg::~EditAttributeListDlg()
{

}

void EditAttributeListDlg::initialize()
{
    if( manApplet->isLicense() == false )
        mSetAttributeBtn->setEnabled( false );
}

void EditAttributeListDlg::setSlotIndex( int index )
{
    slotChanged( index );
}

void EditAttributeListDlg::setObjectType( int type )
{
    object_type_ = type;
}

void EditAttributeListDlg::setObjectID( long id )
{
    object_id_ = id;
}

void EditAttributeListDlg::showEvent(QShowEvent *event)
{
    if( object_type_ < 0 )
        mObjectTypeCombo->addItems(kObjectTypeList);
    else
        mObjectTypeCombo->addItem( kObjectTypeList[object_type_] );

    objectTypeChanged( object_type_ );
}

void EditAttributeListDlg::closeEvent(QCloseEvent *)
{

}


void EditAttributeListDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo;

    slotInfo = slot_infos.at( index );

    session_ = slotInfo.getSessionHandle();

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
    mSlotsCombo->setAcceptDrops(false);
}

void EditAttributeListDlg::labelChanged( int index )
{

    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void EditAttributeListDlg::objectTypeChanged( int type )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;


    if( type == OBJ_DATA_IDX )
    {
        objClass = CKO_DATA;
        setDataAttributes();
    }
    else if( type == OBJ_CERT_IDX )
    {
        objClass = CKO_CERTIFICATE;
        setCertAttributes();
    }
    else if( type == OBJ_PUBKEY_IDX )
    {
        objClass = CKO_PUBLIC_KEY;
        setPublicAttributes();
    }
    else if( type == OBJ_PRIKEY_IDX )
    {
        objClass = CKO_PRIVATE_KEY;
        setPrivateAttributes();
    }
    else if( type == OBJ_SECRET_IDX )
    {
        objClass = CKO_SECRET_KEY;
        setSecretAttributes();
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    if( object_id_ < 0 )
    {
        rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCount );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
        if( rv != CKR_OK ) return;
    }
    else
    {
        uObjCnt = 1;
        sObjects[0] = object_id_;
    }

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        BIN binLabel = {0,0};
        char *pHex = NULL;

        manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        const QVariant objVal =  QVariant( (int)sObjects[i] );

        JS_BIN_string( &binLabel, &pHex );
        mLabelCombo->addItem( pHex, objVal );
        JS_BIN_reset(&binLabel);
    }

    if( uObjCnt > 0 )
    {
        QString strHandle = QString("%1").arg( sObjects[0] );
        mObjectText->setText( strHandle );
    }
}

void EditAttributeListDlg::changeLabel( const QString& text )
{
    int len = text.length() / 2;
    mLabelLenText->setText( QString("%1").arg( len ));
}

void EditAttributeListDlg::changeID( const QString& text )
{
    int len = text.length() / 2;
    mIDLenText->setText( QString("%1").arg( len ));
}

void EditAttributeListDlg::changeApplication( const QString& text )
{
    int len = text.length() / 2;
    mApplicationLenText->setText( QString("%1").arg( len ));
}

void EditAttributeListDlg::changeObjectID( const QString& text )
{
    int len = text.length() / 2;
    mObjectIDLenText->setText( QString("%1").arg( len ));
}

void EditAttributeListDlg::clickLabel()
{
    mLabelText->setEnabled( mLabelCheck->isChecked() );
}

void EditAttributeListDlg::clickID()
{
    mIDText->setEnabled( mIDCheck->isChecked() );
}

void EditAttributeListDlg::clickApplication()
{
    mApplicationText->setEnabled( mApplicationCheck->isChecked() );
}

void EditAttributeListDlg::clickObjectID()
{
    mObjectIDText->setEnabled( mObjectIDCheck->isChecked() );
}

void EditAttributeListDlg::clickClass()
{
    mClassText->setEnabled( mClassCheck->isChecked() );
}

void EditAttributeListDlg::clickKeyType()
{
    mKeyTypeText->setEnabled( mKeyTypeCheck->isCheckable() );
}

void EditAttributeListDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void EditAttributeListDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void EditAttributeListDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void EditAttributeListDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void EditAttributeListDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void EditAttributeListDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void EditAttributeListDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void EditAttributeListDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void EditAttributeListDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}


void EditAttributeListDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}
void EditAttributeListDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void EditAttributeListDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void EditAttributeListDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void EditAttributeListDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void EditAttributeListDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void EditAttributeListDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void EditAttributeListDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void EditAttributeListDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mSensitiveCombo->addItems(sFalseTrue);
    mSensitiveCombo->setCurrentIndex(1);

    mWrapCombo->addItems(sFalseTrue);
    mWrapCombo->setCurrentIndex(1);

    mUnwrapCombo->addItems(sFalseTrue);
    mUnwrapCombo->setCurrentIndex(1);

    mEncryptCombo->addItems(sFalseTrue);
    mEncryptCombo->setCurrentIndex(1);

    mDecryptCombo->addItems(sFalseTrue);
    mDecryptCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mCopyableCombo->addItems(sFalseTrue);
    mCopyableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mSignCombo->addItems(sFalseTrue);
    mSignCombo->setCurrentIndex(1);

    mVerifyCombo->addItems(sFalseTrue);
    mVerifyCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);

    mTrustedCombo->addItems(sFalseTrue);
    mTrustedCombo->setCurrentIndex(1);

    mExtractableCombo->addItems(sFalseTrue);
    mExtractableCombo->setCurrentIndex(1);

    mDeriveCombo->addItems(sFalseTrue);
    mDeriveCombo->setCurrentIndex(1);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void EditAttributeListDlg::setAttributes()
{
    mLabelText->setEnabled( mLabelCheck->isChecked() );
    mIDText->setEnabled( mIDCheck->isChecked() );
    mApplicationText->setEnabled( mApplicationCheck->isChecked() );
    mObjectIDText->setEnabled( mObjectIDCheck->isChecked() );

    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
    mSignCombo->setEnabled(mSignCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    clickDerive();
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void EditAttributeListDlg::connectAttributes()
{
    connect( mLabelCheck, SIGNAL(clicked()), this, SLOT(clickLabel()));
    connect( mIDCheck, SIGNAL(clicked()), this, SLOT(clickID()));
    connect( mApplicationCheck, SIGNAL(clicked()), this, SLOT(clickApplication()));
    connect( mObjectIDCheck, SIGNAL(clicked()), this, SLOT(clickObjectID()));

    connect( mClassCheck, SIGNAL(clicked()), this, SLOT(clickClass()));
    connect( mKeyTypeCheck, SIGNAL(clicked()), this, SLOT(clickKeyType()));

    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptCheck, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mTrustedCheck, SIGNAL(clicked()), this, SLOT(clickTrusted()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void EditAttributeListDlg::setDataAttributes()
{
    mLabelCheck->setEnabled( true );
    mIDCheck->setEnabled( false );
    mApplicationCheck->setEnabled( true );
    mObjectIDCheck->setEnabled( true );

    mClassCheck->setEnabled( true );
    mKeyTypeCheck->setEnabled( false );

    mTokenCheck->setEnabled(true);
    mPrivateCheck->setEnabled(true);
    mModifiableCheck->setEnabled(true);
    mCopyableCheck->setEnabled(true);
    mDestroyableCheck->setEnabled(true);

    mSensitiveCheck->setEnabled(false);
    mWrapCheck->setEnabled(false);
    mUnwrapCheck->setEnabled(false);
    mEncryptCheck->setEnabled(false);
    mDecryptCheck->setEnabled(false);
    mSignCheck->setEnabled(false);
    mVerifyCheck->setEnabled(false);
    mTrustedCheck->setEnabled(false);
    mExtractableCheck->setEnabled(false);
    mDeriveCheck->setEnabled( false );
    mStartDateCheck->setEnabled(false);
    mEndDateCheck->setEnabled(false);
}

void EditAttributeListDlg::setCertAttributes()
{
    mLabelCheck->setEnabled( true );
    mIDCheck->setEnabled( true );
    mApplicationCheck->setEnabled( false );
    mObjectIDCheck->setEnabled( false );

    mClassCheck->setEnabled( true );
    mKeyTypeCheck->setEnabled( false );

    mTokenCheck->setEnabled(true);
    mPrivateCheck->setEnabled(true);
    mModifiableCheck->setEnabled(true);
    mCopyableCheck->setEnabled(true);
    mDestroyableCheck->setEnabled(true);
    mTrustedCheck->setEnabled(true);

    mSensitiveCheck->setEnabled(false);
    mWrapCheck->setEnabled(false);
    mUnwrapCheck->setEnabled(false);
    mEncryptCheck->setEnabled(false);
    mDecryptCheck->setEnabled(false);
    mSignCheck->setEnabled(false);
    mVerifyCheck->setEnabled(false);
    mExtractableCheck->setEnabled(false);
    mDeriveCheck->setEnabled( false );
    mStartDateCheck->setEnabled(false);
    mEndDateCheck->setEnabled(false);
}

void EditAttributeListDlg::setSecretAttributes()
{
    mLabelCheck->setEnabled( true );
    mIDCheck->setEnabled( true );
    mApplicationCheck->setEnabled( false );
    mObjectIDCheck->setEnabled( false );

    mClassCheck->setEnabled( true );
    mKeyTypeCheck->setEnabled( true );

    mPrivateCheck->setEnabled(true);
    mSensitiveCheck->setEnabled(true);
    mWrapCheck->setEnabled(true);
    mUnwrapCheck->setEnabled(true);
    mEncryptCheck->setEnabled(true);
    mDecryptCheck->setEnabled(true);
    mModifiableCheck->setEnabled(true);
    mCopyableCheck->setEnabled(true);
    mDestroyableCheck->setEnabled(true);
    mSignCheck->setEnabled(true);
    mVerifyCheck->setEnabled(true);
    mTokenCheck->setEnabled(true);
    mTrustedCheck->setEnabled(true);
    mExtractableCheck->setEnabled(true);
    mDeriveCheck->setEnabled( true );
    mStartDateCheck->setEnabled(true);
    mEndDateCheck->setEnabled(true);
}

void EditAttributeListDlg::setPublicAttributes()
{
    mLabelCheck->setEnabled( true );
    mIDCheck->setEnabled( true );
    mApplicationCheck->setEnabled( false );
    mObjectIDCheck->setEnabled( false );

    mClassCheck->setEnabled( true );
    mKeyTypeCheck->setEnabled( true );

    mPrivateCheck->setEnabled(true);
    mWrapCheck->setEnabled(true);
    mEncryptCheck->setEnabled(true);
    mModifiableCheck->setEnabled(true);
    mCopyableCheck->setEnabled(true);
    mDestroyableCheck->setEnabled(true);
    mVerifyCheck->setEnabled(true);
    mTokenCheck->setEnabled(true);
    mTrustedCheck->setEnabled(true);
    mExtractableCheck->setEnabled(true);
    mDeriveCheck->setEnabled( true );
    mStartDateCheck->setEnabled(true);
    mEndDateCheck->setEnabled(true);

    mSensitiveCheck->setEnabled(false);
    mSignCheck->setEnabled(false);
    mUnwrapCheck->setEnabled(false);
    mDecryptCheck->setEnabled(false);
}

void EditAttributeListDlg::setPrivateAttributes()
{
    mLabelCheck->setEnabled( true );
    mIDCheck->setEnabled( true );
    mApplicationCheck->setEnabled( false );
    mObjectIDCheck->setEnabled( false );

    mClassCheck->setEnabled( true );
    mKeyTypeCheck->setEnabled( true );

    mPrivateCheck->setEnabled(true);
    mSensitiveCheck->setEnabled(true);
    mUnwrapCheck->setEnabled(true);
    mDecryptCheck->setEnabled(true);
    mModifiableCheck->setEnabled(true);
    mCopyableCheck->setEnabled(true);
    mDestroyableCheck->setEnabled(true);
    mSignCheck->setEnabled(true);
    mTokenCheck->setEnabled(true);
    mTrustedCheck->setEnabled(true);
    mExtractableCheck->setEnabled(true);
    mDeriveCheck->setEnabled( true );
    mStartDateCheck->setEnabled(true);
    mEndDateCheck->setEnabled(true);

    mEncryptCheck->setEnabled(false);
    mVerifyCheck->setEnabled(false);
    mWrapCheck->setEnabled(false);
}

void EditAttributeListDlg::clickGetAttribute()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = -1;
    CK_KEY_TYPE keyType = -1;

    CK_DATE sSDate;
    CK_DATE sEDate;

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    long hObject = mObjectText->text().toLong();

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    memset( sTemplate, 0x00, sizeof(CK_ATTRIBUTE) * 20 );

    if( mLabelCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_LABEL;
        uCount++;
    }

    if( mIDCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ID;
        uCount++;
    }

    if( mApplicationCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_APPLICATION;
        uCount++;
    }

    if( mObjectIDCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_OBJECT_ID;
        uCount++;
    }

    if( mClassCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_CLASS;
        uCount++;
    }

    if( mKeyTypeCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_KEY_TYPE;
        uCount++;
    }

    if( mDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        uCount++;
    }

    if( mEncryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ENCRYPT;
        uCount++;
    }

    if( mModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        uCount++;
    }

    if( mCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        uCount++;
    }

    if( mDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        uCount++;
    }

    if( mPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        uCount++;
    }

    if( mSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SENSITIVE;
        uCount++;
    }

    if( mSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        uCount++;
    }

    if( mTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        uCount++;
    }

    if( mTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        uCount++;
    }

    if( mUnwrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_UNWRAP;
        uCount++;
    }

    if( mVerifyCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY;
        uCount++;
    }

    if( mWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        uCount++;
    }

    if( mExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        uCount++;
    }

    if( mDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;

        uCount++;
    }

    if( mStartDateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_START_DATE;
        uCount++;
    }

    if( mEndDateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_END_DATE;
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->GetAttributeListValue( hSession, hObject, sTemplate, uCount );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to get attribute values(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("Success to get attribute values"), this );

    for( int i = 0; i < uCount; i++ )
    {
        if( sTemplate[i].type == CKA_LABEL )
        {
            mLabelText->setText( QString("%1").arg(getHexString( (unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen)));
        }
        else if( sTemplate[i].type == CKA_ID )
        {
            mIDText->setText( QString("%1").arg(getHexString( (unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen)));
        }
        else if( sTemplate[i].type == CKA_APPLICATION )
        {
            mApplicationText->setText( QString("%1").arg(getHexString( (unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen)));
        }
        else if( sTemplate[i].type == CKA_OBJECT_ID )
        {
            mObjectIDText->setText( QString("%1").arg(getHexString( (unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen)));
        }
        else if( sTemplate[i].type == CKA_CLASS )
        {
            mClassText->setText( QString("%1").arg(getHexString( (unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen)));
        }
        else if( sTemplate[i].type == CKA_KEY_TYPE )
        {
            mKeyTypeText->setText( QString("%1").arg(getHexString( (unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen)));
        }
        else if( sTemplate[i].type == CKA_DECRYPT )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mDecryptCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_ENCRYPT )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mEncryptCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_MODIFIABLE )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mModifiableCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_COPYABLE )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mCopyableCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_DESTROYABLE )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mDestroyableCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_PRIVATE )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mPrivateCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_SENSITIVE )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mSensitiveCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_SIGN )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mSignCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_TOKEN )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mTokenCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_TRUSTED )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mTrustedCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_UNWRAP )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mUnwrapCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_VERIFY )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mVerifyCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_WRAP )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mWrapCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_EXTRACTABLE )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mExtractableCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_DERIVE )
        {
            if( sTemplate[i].ulValueLen > 0 )
            {
                unsigned char *pPtr = (unsigned char *)sTemplate[i].pValue;
                mDeriveCombo->setCurrentIndex( pPtr[0] );
            }
        }
        else if( sTemplate[i].type == CKA_START_DATE )
        {
            if( sTemplate[i].ulValueLen == sizeof(CK_DATE))
            {
                CK_DATE ckDate;
                QDate date;

                memcpy( &ckDate, sTemplate[i].pValue, sTemplate[i].ulValueLen );
                getCKDateToQDate( &ckDate, &date );

                mStartDateEdit->setDate( date );
            }
        }
        else if( sTemplate[i].type == CKA_END_DATE )
        {
            if( sTemplate[i].ulValueLen == sizeof(CK_DATE))
            {
                CK_DATE ckDate;
                QDate date;

                memcpy( &ckDate, sTemplate[i].pValue, sTemplate[i].ulValueLen );
                getCKDateToQDate( &ckDate, &date );

                mStartDateEdit->setDate( date );
            }
        }


        if( sTemplate[i].pValue ) JS_free( sTemplate[i].pValue );
    }
}

void EditAttributeListDlg::clickSetAttribute()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = 0;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    long hObject = mObjectText->text().toLong();

    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binApplication = {0,0};
    BIN binOID = {0,0};

    BIN binClass = {0,0};
    BIN binKeyType = {0,0};

    QString strLabel = mLabelText->text();
    QString strID = mIDText->text();
    QString strApplication = mApplicationText->text();
    QString strOID = mObjectIDText->text();
    QString strClass = mClassText->text();
    QString strKeyType = mKeyTypeText->text();


    if( mLabelCheck->isChecked() )
    {
        JS_BIN_decodeHex( strLabel.toStdString().c_str(), &binLabel );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    if( mIDCheck->isChecked() )
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    if( mApplicationCheck->isChecked() )
    {
        JS_BIN_decodeHex( strApplication.toStdString().c_str(), &binApplication );

        sTemplate[uCount].type = CKA_APPLICATION;
        sTemplate[uCount].pValue = binApplication.pVal;
        sTemplate[uCount].ulValueLen = binApplication.nLen;
        uCount++;
    }

    if( mObjectIDCheck->isChecked() )
    {
        JS_BIN_decodeHex( strOID.toStdString().c_str(), &binOID );

        sTemplate[uCount].type = CKA_OBJECT_ID;
        sTemplate[uCount].pValue = binOID.pVal;
        sTemplate[uCount].ulValueLen = binOID.nLen;
        uCount++;
    }

    if( mClassCheck->isChecked() )
    {
        JS_BIN_decodeHex( strClass.toStdString().c_str(), &binClass );

        sTemplate[uCount].type = CKA_CLASS;
        sTemplate[uCount].pValue = binClass.pVal;
        sTemplate[uCount].ulValueLen = binClass.nLen;
        uCount++;
    }

    if( mKeyTypeCheck->isChecked() )
    {
        JS_BIN_decodeHex( strKeyType.toStdString().c_str(), &binKeyType );

        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = binKeyType.pVal;
        sTemplate[uCount].ulValueLen = binKeyType.nLen;
        uCount++;
    }

    if( mObjectIDCheck->isChecked() )
    {
        JS_BIN_decodeHex( strOID.toStdString().c_str(), &binOID );

        sTemplate[uCount].type = CKA_OBJECT_ID;
        sTemplate[uCount].pValue = binOID.pVal;
        sTemplate[uCount].ulValueLen = binOID.nLen;
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

    if( mCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mTrustedCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = ( mExtractableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = ( mDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->SetAttributeValue( hSession, hObject, sTemplate, uCount );

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binApplication );
    JS_BIN_reset( &binOID );
    JS_BIN_reset( &binClass );
    JS_BIN_reset( &binKeyType );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "SetAttributeValue execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("SetAttributeValue execution successful"), this );
}
