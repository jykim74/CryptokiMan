/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "set_pin_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

SetPinDlg::SetPinDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initialize();
    mOldPinText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SetPinDlg::~SetPinDlg()
{

}


void SetPinDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotInfoText->setText( getSlotInfo( slot_info_) );
        mSlotInfoText->setCursorPosition(0);
        mSlotBtn->setIcon( getSlotIcon( slot_info_ ) );
    }
}

void SetPinDlg::initialize()
{

}

void SetPinDlg::accept()
{
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();
    int rv = -1;

    QString strOldPin = mOldPinText->text();

    if( strOldPin.isEmpty() )
    {
        manApplet->warningBox( tr( "Please enter old PIN"), this );
        mOldPinText->setFocus();;
        return;
    }

    QString strNewPin = mNewPinText->text();
    if( strNewPin.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter new PIN"), this );
        mNewPinText->setFocus();;
        return;
    }

    QString strPinConf = mPinConfText->text();
    if( strNewPin != strPinConf )
    {
        manApplet->warningBox( tr( "New PIN and PIN confirm values are different" ), this );
        mPinConfText->setFocus();

        return;
    }

    BIN binOldPin = {0,0};
    BIN binNewPin = { 0,0 };

    rv = getBINFromString( &binOldPin, DATA_STRING, strOldPin );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    rv = getBINFromString( &binNewPin, DATA_STRING, strNewPin );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    rv = manApplet->cryptokiAPI()->SetPIN( hSession, binOldPin.pVal, binOldPin.nLen, binNewPin.pVal, binNewPin.nLen );

    JS_BIN_reset( &binOldPin );
    JS_BIN_reset( &binNewPin );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "SetPIN execution failure [%1]").arg(rv), this );
        return;
    }

    manApplet->messageBox( tr( "SetPIN execution successful"), this );
    QDialog::accept();
}
