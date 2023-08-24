#include "login_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"

const QStringList kLoginType = { "SO", "User" };

LoginDlg::LoginDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mLoginBtn, SIGNAL(clicked()), this, SLOT(clickLogin()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();
}

LoginDlg::~LoginDlg()
{

}

void LoginDlg::setSelectedSlot(int index)
{
    if( index >= 0 )
        mSlotsCombo->setCurrentIndex(index);
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
    mPinText->setEchoMode(QLineEdit::Password);

    mTypeCombo->addItems( kLoginType );
    mTypeCombo->setCurrentIndex(1);
    mLoginBtn->setDefault(true);
}

void LoginDlg::clickLogin()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nType = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    if( (long)hSession == -1 )
    {
        manApplet->warningBox( tr( "need to open session" ), this );
        return;
    }

    int rv = -1;
    CK_UTF8CHAR *pPin = (CK_UTF8CHAR *)mPinText->text().toUtf8().toStdString().c_str();
    CK_ULONG uPinLen = mPinText->text().toUtf8().length();

    if( mTypeCombo->currentText() == "SO" )
        nType = CKU_SO;
    else
        nType = CKU_USER;

    rv = manApplet->cryptokiAPI()->Login( hSession, nType, pPin, uPinLen );

    if( rv == CKR_OK )
    {
        slotInfo.setLogin(true);
        slot_infos.replace( index, slotInfo );
        manApplet->log( "Login OK" );
        manApplet->messageBox( tr( "Login OK" ), this );
    }
    else {
        manApplet->warningBox( tr( "Login fail"), this );
        manApplet->elog( QString("C_Login fail:%1").arg(rv));
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
