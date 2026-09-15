#include <QDialog>
#include <QLayout>

#include "create_pqc_pub_key_dlg.h"

CreatePQCPubKeyDlg::CreatePQCPubKeyDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CreatePQCPubKeyDlg::~CreatePQCPubKeyDlg()
{

}
