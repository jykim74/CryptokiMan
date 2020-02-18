#include "man_applet.h"
#include "mainwindow.h"
#include "open_session_dlg.h"
#include "js_pkcs11.h"


OpenSessionDlg::OpenSessionDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initialize();
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
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);

    if( mRWCheck->isChecked() )
        nFlags |= CKF_RW_SESSION;

    if( mSerialCheck->isChecked() )
        nFlags |= CKF_SERIAL_SESSION;

    int rv = JS_PKCS11_OpenSession( p11_ctx, slotInfo.getSlotID(), nFlags, &hSession );

    if( rv == CKR_OK )
    {
        slotInfo.setSessionHandle( hSession );
        slot_infos.replace(index, slotInfo);
        manApplet->messageBox( tr("OpenSession is success"), this );
    }
    else {
        manApplet->warningBox( tr("OpenSession is failure"), this );
        return;
    }

    QDialog::accept();
}
