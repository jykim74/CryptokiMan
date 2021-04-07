#ifndef GEN_DATA_DLG_H
#define GEN_DATA_DLG_H

#include <QDialog>
#include "ui_create_data_dlg.h"

namespace Ui {
class CreateDataDlg;
}

class CreateDataDlg : public QDialog, public Ui::CreateDataDlg
{
    Q_OBJECT

public:
    explicit CreateDataDlg(QWidget *parent = nullptr);
    ~CreateDataDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickPrivate();
    void clickSensitive();
    void clickModifiable();
    void clickToken();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // GEN_DATA_DLG_H
