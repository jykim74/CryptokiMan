#ifndef OPER_STATE_DLG_H
#define OPER_STATE_DLG_H

#include <QDialog>
#include "ui_oper_state_dlg.h"

namespace Ui {
class OperStateDlg;
}

class OperStateDlg : public QDialog, public Ui::OperStateDlg
{
    Q_OBJECT

public:
    explicit OperStateDlg(QWidget *parent = nullptr);
    ~OperStateDlg();

private slots:
    void slotChanged(int index );
    void clickGetOperationState();
    void clickSetOperationState();

private:
    void initialize();
};

#endif // OPER_STATE_DLG_H
