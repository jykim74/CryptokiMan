/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "close_session_dlg.h"
#include "js_pkcs11.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cryptoki_api.h"

CloseSessionDlg::CloseSessionDlg(QWidget *parent) :
    QDialog(parent)
{
    all_ = false;
    setupUi(this);
    setWindowTitle( "CloseSession Dialog" );

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CloseSessionDlg::~CloseSessionDlg()
{

}

void CloseSessionDlg::setAll(bool all)
{
    all_ = all;
    setWindowTitle( "Close all sessions" );
}

void CloseSessionDlg::initialize()
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

void CloseSessionDlg::setSelectedSlot(int index)
{
    if( index >= 0 )
        mSlotsCombo->setCurrentIndex(index);
}

void CloseSessionDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    QString strType = "";

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    if( all_ )
    {
        rv = manApplet->cryptokiAPI()->CloseAllSession( slotInfo.getSlotID() );
        strType = "All";
    }
    else {
        rv = manApplet->cryptokiAPI()->CloseSession( hSession );
        strType = "Single";
    }

    if( rv == CKR_OK )
    {
        if( all_ )
        {
            for( int i=0; i < slot_infos.size(); i++ )
            {
                SlotInfo tmpInfo = slot_infos.at(i);
                tmpInfo.setSessionHandle(-1);
                tmpInfo.setLogin(false);
                slot_infos.replace( i, tmpInfo );
            }
        }
        else {
            slotInfo.setSessionHandle(-1);
            slotInfo.setLogin( false );
            slot_infos.replace( index, slotInfo );
        }

        manApplet->messageBox( tr("CloseSession(%1) successful").arg(strType), this );
        QDialog::accept();
    }
    else {
        if( all_ )
        {
            manApplet->warningBox( tr("CloseAllSessions(%1) failure [%2]").arg(strType).arg(rv), this );
        }
        else
        {
            manApplet->warningBox( tr("CloseSession(%1) failure [%2]").arg(strType).arg(rv), this );
        }

        return;
    }
}

void CloseSessionDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}
