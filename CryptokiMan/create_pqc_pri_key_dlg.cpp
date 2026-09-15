#include <QDialog>
#include <QLayout>

#include "create_pqc_pri_key_dlg.h"
#include "ui_create_pqc_pri_key_dlg.h"
#include "common.h"

CreatePQCPriKeyDlg::CreatePQCPriKeyDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CreatePQCPriKeyDlg::~CreatePQCPriKeyDlg()
{

}
