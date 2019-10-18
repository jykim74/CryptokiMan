#ifndef EDIT_ATTRIBUTE_DLG_H
#define EDIT_ATTRIBUTE_DLG_H

#include <QDialog>
#include "ui_edit_attribute_dlg.h"

namespace Ui {
class EditAttributeDlg;
}

class EditAttributeDlg : public QDialog, public Ui::EditAttributeDlg
{
    Q_OBJECT

public:
    explicit EditAttributeDlg(QWidget *parent = nullptr);
    ~EditAttributeDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

    void clickClose();
    void clickGetAttribute();
    void clickSetAttribute();

private:
    void initialize();
    void initAttributes();
};

#endif // EDIT_ATTRIBUTE_DLG_H
