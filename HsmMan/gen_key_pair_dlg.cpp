#include "man_applet.h"
#include "mainwindow.h"
#include "gen_key_pair_dlg.h"
#include "js_pkcs11.h"

static QStringList sMechList = { "RSA", "ECC" };
static QStringList sRSAOptionList = { "1024", "2048", "3096", "4082" };

static QStringList sECOptionList = {
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192k1", "secp224k1", "secp224r1",
    "secp256k1", "secp384r1", "secp521r1", "sect113r1", "sect113r2",
    "sect131r1", "sect131r2", "sect163k1", "sect163r1", "sect163r2",
    "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1",
    "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1",
    "sect571r1"
};

static QStringList sFalseTrue = { "false", "true" };

GenKeyPairDlg::GenKeyPairDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));
}

GenKeyPairDlg::~GenKeyPairDlg()
{

}

void GenKeyPairDlg::showEvent(QShowEvent* event )
{
    initialize();
}

void GenKeyPairDlg::initialize()
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

void GenKeyPairDlg::initAttributes()
{
    mMechCombo->addItems( sMechList );

    mOptionCombo->addItems( sRSAOptionList );

    mPriPrivateCombo->addItems( sFalseTrue );
    mPriDecryptCombo->addItems( sFalseTrue );
    mPriSignCombo->addItems( sFalseTrue );
    mPriUnwrapCombo->addItems( sFalseTrue );
    mPriModifiableCombo->addItems( sFalseTrue );
    mPriSensitiveCombo->addItems( sFalseTrue );
    mPriDeriveCombo->addItems( sFalseTrue );
    mPriExtractableCombo->addItems( sFalseTrue );
    mPriTokenCombo->addItems( sFalseTrue );

    mPubPrivateCombo->addItems( sFalseTrue );
    mPubEncryptCombo->addItems( sFalseTrue );
    mPubWrapCombo->addItems( sFalseTrue );
    mPubVerifyCombo->addItems( sFalseTrue );
    mPubDeriveCombo->addItems( sFalseTrue );
    mPubModifiableCombo->addItems( sFalseTrue );
    mPubTokenCombo->addItems( sFalseTrue );
}

void GenKeyPairDlg::setAttributes()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
    mPriSignCombo->setEnabled( mPriSignCheck->isChecked() );
    mPriUnwrapCombo->setEnabled( mPriUnwrapCheck->isChecked() );
    mPriModifiableCombo->setEnabled( mPriModifiableCheck->isChecked() );
    mPriSensitiveCombo->setEnabled( mPriSensitiveCheck->isChecked() );
    mPriDeriveCombo->setEnabled( mPriDeriveCheck->isChecked() );
    mPriExtractableCombo->setEnabled( mPriExtractableCheck->isChecked() );
    mPriTokenCombo->setEnabled( mPriTokenCheck->isChecked() );

    mPubPrivateCombo->setEnabled( mPubPrivateCheck->isChecked() );
    mPubEncryptCombo->setEnabled( mPubEncryptCheck->isChecked() );
    mPubWrapCombo->setEnabled( mPubWrapCheck->isChecked() );
    mPubVerifyCombo->setEnabled( mPubVerifyCheck->isChecked() );
    mPubDeriveCombo->setEnabled( mPubDeriveCheck->isChecked() );
    mPubModifiableCombo->setEnabled( mPubModifiableCheck->isChecked() );
    mPubTokenCombo->setEnabled( mPubTokenCheck->isChecked() );
}

void GenKeyPairDlg::connectAttributes()
{
    connect( mPriPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPriPrivate()));
    connect( mPriDecryptCheck, SIGNAL(clicked()), this, SLOT(clickPriDecrypt()));
    connect( mPriSignCheck, SIGNAL(clicked()), this, SLOT(clickPriSign()));
    connect( mPriUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickPriUnwrap()));
    connect( mPriModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPriModifiable()));
    connect( mPriSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickPriSensitive()));
    connect( mPriDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPriDerive()));
    connect( mPriExtractableCheck, SIGNAL(clicked()), this, SLOT(clickPriExtractable()));
    connect( mPriTokenCheck, SIGNAL(clicked()), this, SLOT(clickPriToken()));

    connect( mPubPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPubPrivate()));
    connect( mPubEncryptCheck, SIGNAL(clicked()), this, SLOT(clickPubEncrypt()));
    connect( mPubWrapCheck, SIGNAL(clicked()), this, SLOT(clickPubWrap()));
    connect( mPubVerifyCheck, SIGNAL(clicked()), this, SLOT(clickPubVerify()));
    connect( mPubDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPubDerive()));
    connect( mPubModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPubModifiable()));
    connect( mPubTokenCheck, SIGNAL(clicked()), this, SLOT(clickPubToken()));
}

void GenKeyPairDlg::accept()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
    int rv = -1;


}

void GenKeyPairDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void GenKeyPairDlg::mechChanged(int nIndex)
{
    mOptionCombo->clear();

    if( nIndex == 0 )
    {
        mOptionLabel->setText( QString("Key size") );
        mOptionCombo->addItems( sRSAOptionList );
    }
    else
    {
        mOptionLabel->setText( QString("NamedCurve"));
        mOptionCombo->addItems( sECOptionList );
    }
}

void GenKeyPairDlg::clickPriPrivate()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
}

void GenKeyPairDlg::clickPriDecrypt()
{
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
}

void GenKeyPairDlg::clickPriSign()
{
    mPriSignCombo->setEnabled(mPriSignCheck->isChecked());
}

void GenKeyPairDlg::clickPriUnwrap()
{
    mPriUnwrapCombo->setEnabled(mPriUnwrapCheck->isChecked());
}
void GenKeyPairDlg::clickPriModifiable()
{
    mPriModifiableCombo->setEnabled(mPriModifiableCheck->isChecked());
}
void GenKeyPairDlg::clickPriSensitive()
{
    mPriSensitiveCombo->setEnabled(mPriSensitiveCheck->isChecked());
}
void GenKeyPairDlg::clickPriDerive()
{
    mPriDeriveCombo->setEnabled(mPriDeriveCheck->isChecked());
}
void GenKeyPairDlg::clickPriExtractable()
{
    mPriExtractableCombo->setEnabled(mPriExtractableCheck->isChecked());
}
void GenKeyPairDlg::clickPriToken()
{
    mPriTokenCombo->setEnabled(mPriTokenCheck->isChecked());
}

void GenKeyPairDlg::clickPubPrivate()
{
    mPubPrivateCombo->setEnabled(mPubPrivateCheck->isChecked());
}
void GenKeyPairDlg::clickPubEncrypt()
{
    mPubEncryptCombo->setEnabled(mPubEncryptCheck->isChecked());
}
void GenKeyPairDlg::clickPubWrap()
{
    mPubWrapCombo->setEnabled(mPubWrapCheck->isChecked());
}
void GenKeyPairDlg::clickPubVerify()
{
    mPubVerifyCombo->setEnabled(mPubVerifyCheck->isChecked());
}
void GenKeyPairDlg::clickPubDerive()
{
    mPubDeriveCombo->setEnabled(mPubDeriveCheck->isChecked());
}
void GenKeyPairDlg::clickPubModifiable()
{
    mPubModifiableCombo->setEnabled(mPubModifiableCheck->isChecked());
}
void GenKeyPairDlg::clickPubToken()
{
    mPubTokenCombo->setEnabled(mPubTokenCheck->isChecked());
}
