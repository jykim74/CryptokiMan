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

void RandDlg::showEvent(QShowEvent* event )
{
    initialize();
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
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
    int rv = -1;
    hSession = slotInfo.getSessionHandle();

    QString strLen = mLengthText->text();

    if( strLen.isEmpty() )
    {
        QMessageBox::warning( this, "Random", "You have to insert random length" );
        return;
    }

    CK_BYTE_PTR pRand = NULL;

    pRand = (CK_BYTE_PTR)JS_malloc( strLen.toInt() );

    rv = JS_PKCS11_GenerateRandom( p11_ctx, hSession, pRand, strLen.toInt());
    if( rv != CKR_OK )
    {
        if( pRand ) JS_free( pRand );
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
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
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

    rv = JS_PKCS11_SeedRandom( p11_ctx, hSession, binSeed.pVal, binSeed.nLen );

    if( rv != CKR_OK )
    {
        return;
    }

    QMessageBox::information( this, "Random", "SeedRandom OK." );
}
