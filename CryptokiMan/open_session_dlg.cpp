#include "man_applet.h"
#include "mainwindow.h"
#include "open_session_dlg.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"

OpenSessionDlg::OpenSessionDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mOpenSessionBtn, SIGNAL(clicked()), this, SLOT(clickOpenSession()));
    connect( mWaitForSlotEventBtn, SIGNAL(clicked()), this, SLOT(clickWaitForSlotEvent()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();

    mOpenSessionBtn->setFocus();
}

OpenSessionDlg::~OpenSessionDlg()
{

}

void OpenSessionDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }
}

void OpenSessionDlg::setSelectedSlot(int index)
{
    if( index >= 0 )
        mSlotsCombo->setCurrentIndex(index);
}

void OpenSessionDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = 0;

    if( mRWCheck->isChecked() )
        nFlags |= CKF_RW_SESSION;

    if( mSerialCheck->isChecked() )
        nFlags |= CKF_SERIAL_SESSION;

    int rv = manApplet->cryptokiAPI()->OpenSession( slotInfo.getSlotID(), nFlags, NULL, NULL, &hSession );

    if( rv == CKR_OK )
    {
        slotInfo.setSessionHandle( hSession );
        slot_infos.replace(index, slotInfo);

        manApplet->messageLog( tr( "OpenSession execution successful"), this );
    }
    else {
        manApplet->warnLog( tr("OpenSession execution failure [%1:%2]").arg( JS_PKCS11_GetErrorMsg(rv)).arg(rv), this );
        return;
    }

    QDialog::accept();
}

void OpenSessionDlg::clickOpenSession()
{
    accept();
}

void OpenSessionDlg::clickWaitForSlotEvent()
{
    int rv = -1;
    CK_ULONG uFlags = 0;
    CK_SLOT_ID uSlotID = 0;

    rv = manApplet->cryptokiAPI()->WaitForSlotEvent( uFlags, &uSlotID, NULL );

    manApplet->messageBox( QString( "WaitForSlotEvent Ret: %1 [%2]").arg( JS_PKCS11_GetErrorMsg(rv) ).arg(rv), this );
}
