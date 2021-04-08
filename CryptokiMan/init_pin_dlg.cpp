#include "init_pin_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"

InitPinDlg::InitPinDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    initialize();
}

InitPinDlg::~InitPinDlg()
{

}


void InitPinDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void InitPinDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void InitPinDlg::initialize()
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

void InitPinDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();
    QString strPin = mPinText->text();

    if( strPin.isEmpty() )
    {
        manApplet->warningBox( tr( "Insert pin value"), this );
        mPinText->setFocus();;

        return;
    }

    BIN binPin = {0,0};
    JS_BIN_set( &binPin, (unsigned char *)strPin.toStdString().c_str(), strPin.length() );

    rv = JS_PKCS11_InitPIN( p11_ctx, binPin.pVal, binPin.nLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to run InitPIN(%1)").arg(rv), this );
        JS_BIN_reset( &binPin );
        return;
    }

    manApplet->messageBox( tr( "Success to run InitPIN"), this );
    JS_BIN_reset( &binPin );
    QDialog::accept();
}
