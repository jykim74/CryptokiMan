#include "rand_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"

static QStringList sSeedList = { "String", "Hex", "Base64" };

RandDlg::RandDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
}

RandDlg::~RandDlg()
{

}

void RandDlg::initUI()
{
    mSeedCombo->addItems( sSeedList );

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mSetSeedBtn, SIGNAL(clicked()), this, SLOT(clickSeed()));

    initialize();
}

void RandDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void RandDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void RandDlg::initialize()
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

void RandDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    if( p11_ctx == NULL ) return;

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    if( slot_infos.size() <= 0 ) return;

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    QString strLen = mLengthText->text();

    if( strLen.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert length value"), this );
        return;
    }

    CK_BYTE_PTR pRand = NULL;

    pRand = (CK_BYTE_PTR)JS_malloc( strLen.toInt() );

    rv = JS_PKCS11_GenerateRandom( p11_ctx, pRand, strLen.toInt());
    manApplet->logP11Result( "C_GenerateRandom", rv );

    if( rv != CKR_OK )
    {
        if( pRand ) JS_free( pRand );
        manApplet->warningBox( tr( "fail to generate random(%1)").arg(rv), this );
        return;
    }

    BIN binRand = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binRand, pRand, strLen.toInt());
    JS_BIN_encodeHex( &binRand, &pHex );
    JS_free( pRand );

    mOutputText->setPlainText( pHex );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binRand);
}

void RandDlg::clickSeed()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    p11_ctx->hSession = slotInfo.getSessionHandle();
    int rv = -1;

    QString strSeed = mSeedText->text();

    if( strSeed.isEmpty() )
    {
        manApplet->warningBox(tr("You have to insert seed value."), this );
        return;
    }

    BIN binSeed = {0,0};
    if( mSeedCombo->currentIndex() == 0 )
        JS_BIN_set( &binSeed, (unsigned char *)strSeed.toStdString().c_str(), strSeed.length() );
    else if( mSeedCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strSeed.toStdString().c_str(), &binSeed );
    else if( mSeedCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strSeed.toStdString().c_str(), &binSeed );

    rv = JS_PKCS11_SeedRandom( p11_ctx, binSeed.pVal, binSeed.nLen );
    manApplet->logP11Result( "C_SeedRandom", rv );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to run SeedRandom(%1)").arg(rv), this );
        return;
    }

    manApplet->warningBox( tr("SeedRandom is OK"), this );
}
