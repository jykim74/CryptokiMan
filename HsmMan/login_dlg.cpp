#include "login_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

LoginDlg::LoginDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
}

LoginDlg::~LoginDlg()
{

}

void LoginDlg::showEvent(QShowEvent* event )
{
    initialize();
}

void LoginDlg::initialize()
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

void LoginDlg::accept()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    int nType = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();
    int rv = -1;
    CK_UTF8CHAR *pPin = (CK_UTF8CHAR *)mPinText->text().toUtf8().toStdString().c_str();
    CK_ULONG uPinLen = mPinText->text().toUtf8().length();

    rv = JS_PKCS11_Login( p11_ctx, hSession, nType, pPin, uPinLen );

    if( rv == CKR_OK )
    {
        slotInfo.setLogin(true);
        slot_infos.replace( index, slotInfo );
        manApplet->messageBox( tr("Login is success"), this);
    }
    else {
        manApplet->messageBox( tr("Login is failure"), this);
    }

    QDialog::close();
}

void LoginDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
}
