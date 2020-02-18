#include "logout_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"


LogoutDlg::LogoutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));

    initialize();
}

LogoutDlg::~LogoutDlg()
{

}

void LogoutDlg::setSelectedSlot(int index)
{
    if( index >= 0 )
        mSlotsCombo->setCurrentIndex(index);
}

void LogoutDlg::initialize()
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

void LogoutDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    rv = JS_PKCS11_Logout( p11_ctx, slotInfo.getSessionHandle() );
    if( rv == CKR_OK )
    {
        slotInfo.setLogin(false);
        slot_infos.replace(index, slotInfo);
        manApplet->messageBox(tr("Logout is success"), this );
    }
    else {
        manApplet->warningBox(tr("Logout is failure"), this );
    }

    QDialog::accept();
}

void LogoutDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}
