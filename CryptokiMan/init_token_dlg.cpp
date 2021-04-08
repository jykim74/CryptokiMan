#include "init_token_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

InitTokenDlg::InitTokenDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();
}

InitTokenDlg::~InitTokenDlg()
{

}


void InitTokenDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void InitTokenDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void InitTokenDlg::initialize()
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

void InitTokenDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();
    int rv = -1;


    QString strPIN = mPinText->text();

    if( strPIN.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert PIN."), this );
        mPinText->setFocus();

        return;
    }

    QString strLabel = mLabelText->text();
    if( strLabel.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert label."), this );
        mLabelText->setFocus();

        return;
    }

    rv = JS_PKCS11_InitToken( p11_ctx, slotInfo.getSlotID(), (CK_UTF8CHAR_PTR)strPIN.toStdString().c_str(),
                              strPIN.length(), (CK_UTF8CHAR_PTR)strLabel.toStdString().c_str() );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to initialize token(%1)").arg(rv), this );
        return;
    }

    QDialog::accept();
}
