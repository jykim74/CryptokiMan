#include "set_pin_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"

SetPinDlg::SetPinDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    initialize();
}

SetPinDlg::~SetPinDlg()
{

}


void SetPinDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void SetPinDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void SetPinDlg::initialize()
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

void SetPinDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    p11_ctx->hSession = slotInfo.getSessionHandle();
    int rv = -1;


    QString strOldPin = mOldPinText->text();

    if( strOldPin.isEmpty() )
    {
        manApplet->warningBox( tr( "Insert old pin value"), this );
        mOldPinText->setFocus();;
        return;
    }

    QString strNewPin = mNewPinText->text();
    if( strNewPin.isEmpty() )
    {
        manApplet->warningBox( tr(" Insert new pin value"), this );
        mNewPinText->setFocus();;
        return;
    }

    BIN binOldPin = {0,0};
    BIN binNewPin = { 0,0 };


    JS_BIN_set( &binOldPin, (unsigned char *)strOldPin.toStdString().c_str(), strOldPin.length() );
    JS_BIN_set( &binNewPin, (unsigned char *)strNewPin.toStdString().c_str(), strNewPin.length() );


    rv = JS_PKCS11_SetPIN( p11_ctx, binOldPin.pVal, binOldPin.nLen, binNewPin.pVal, binNewPin.nLen );
    manApplet->logP11Result( "C_SetPIN", rv );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to run C_SetPIN(%1)").arg(rv), this );
        JS_BIN_reset( &binOldPin );
        JS_BIN_reset( &binNewPin );
        return;
    }

    manApplet->messageBox( tr( "success to run C_SetPIN"), this );
    JS_BIN_reset( &binNewPin );
    JS_BIN_reset( &binOldPin );
    QDialog::accept();
}
