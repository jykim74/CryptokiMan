#include "set_pin_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"

SetPinDlg::SetPinDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
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

void SetPinDlg::showEvent(QShowEvent* event )
{
    initialize();
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
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
    hSession = slotInfo.getSessionHandle();
    int rv = -1;


    QString strOldPin = mOldPinText->text();

    if( strOldPin.isEmpty() )
    {
        QMessageBox::warning( this, "SetPIN", "You have to insert old pin." );
        mOldPinText->setFocus();;
        return;
    }

    QString strNewPin = mNewPinText->text();
    if( strNewPin.isEmpty() )
    {
        QMessageBox::warning( this, "SetPIN", "You have to insert new pin." );
        mNewPinText->setFocus();;
        return;
    }

    BIN binOldPin = {0,0};
    BIN binNewPin = { 0,0 };


    JS_BIN_set( &binOldPin, (unsigned char *)strOldPin.toStdString().c_str(), strOldPin.length() );
    JS_BIN_set( &binNewPin, (unsigned char *)strNewPin.toStdString().c_str(), strNewPin.length() );


    rv = JS_PKCS11_SetPIN( p11_ctx, hSession, binOldPin.pVal, binOldPin.nLen, binNewPin.pVal, binNewPin.nLen );
    if( rv != CKR_OK )
    {
        return;
    }

    QDialog::accept();
}
