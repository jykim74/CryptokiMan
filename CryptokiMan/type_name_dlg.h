#ifndef TYPE_NAME_DLG_H
#define TYPE_NAME_DLG_H

#include <QDialog>
#include "ui_type_name_dlg.h"

namespace Ui {
class TypeNameDlg;
}

enum {
    JTypeName = 0,
    JTypeDecimail = 1,
    JTypeHex = 2
};

class TypeNameDlg : public QDialog, public Ui::TypeNameDlg
{
    Q_OBJECT

public:
    explicit TypeNameDlg(QWidget *parent = nullptr);
    ~TypeNameDlg();

private slots:
    void clickClear();
    void clickSearch();

private:
    void initialize();
    int getType( const QString strInput );
};

#endif // TYPE_NAME_DLG_H
