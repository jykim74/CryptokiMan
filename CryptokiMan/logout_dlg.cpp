/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "logout_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"


LogoutDlg::LogoutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

LogoutDlg::~LogoutDlg()
{

}

void LogoutDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
//        mSlotInfoText->setText( getSlotInfo( slot_info_) );
        mSlotInfoText->setText( slot_info_.getDesc() );
        mSlotBtn->setIcon( getSlotIcon( slot_info_ ) );
    }
}

void LogoutDlg::initialize()
{

}

void LogoutDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_SESSION_HANDLE   hSession = -1;
    int rv = -1;
    hSession = slot_info_.getSessionHandle();

    if( (long)hSession == -1 )
    {
        manApplet->warningBox( tr( "OpenSession is required" ), this );
        return;
    }

    rv = manApplet->cryptokiAPI()->Logout( hSession );

    if( rv == CKR_OK )
    {
        slot_info_.setLogin(false);
        slot_infos.replace(slot_index_, slot_info_);

        QDialog::accept();
    }
    else {
        manApplet->warningBox(tr("Logout failure [%1]").arg(rv), this );
        QDialog::reject();
    }
}
