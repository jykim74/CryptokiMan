#ifndef WRAP_KEY_DLG_H
#define WRAP_KEY_DLG_H

#include <QDialog>
#include "ui_wrap_key_dlg.h"

namespace Ui {
class WrapKeyDlg;
}

class WrapKeyDlg : public QDialog, public Ui::WrapKeyDlg
{
    Q_OBJECT

public:
    explicit WrapKeyDlg(QWidget *parent = nullptr);
    ~WrapKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void labelChanged(int index );
    void wrappingLabelChanged(int index );
    void clickFind();

private:
    void initialize();
    void initUI();
    void setWrapLabelList();

    int slot_index_;
    long session_;
};

#endif // WRAP_KEY_DLG_H
