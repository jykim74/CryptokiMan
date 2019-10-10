#ifndef CLOSE_SESSION_DLG_H
#define CLOSE_SESSION_DLG_H

#include <QDialog>
#include "ui_close_session_dlg.h"

namespace Ui {
class CloseSessionDlg;
}

class CloseSessionDlg : public QDialog, public Ui::CloseSessionDlg
{
    Q_OBJECT

public:
    explicit CloseSessionDlg(QWidget *parent = nullptr);
    ~CloseSessionDlg();

private:

};

#endif // CLOSE_SESSION_DLG_H
