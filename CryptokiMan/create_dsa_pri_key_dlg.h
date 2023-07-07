#ifndef GEN_DSA_PRI_KEY_DLG_H
#define GEN_DSA_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_create_dsa_pri_key_dlg.h"

namespace Ui {
class CreateDSAPriKeyDlg;
}

class CreateDSAPriKeyDlg : public QDialog, public Ui::CreateDSAPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreateDSAPriKeyDlg(QWidget *parent = nullptr);
    ~CreateDSAPriKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickPrivate();
    void clickDecrypt();
    void clickSign();
    void clickUnwrap();
    void clickModifiable();
    void clickSensitive();
    void clickDerive();
    void clickExtractable();
    void clickToken();
    void clickStartDate();
    void clickEndDate();

    void changeP( const QString& text );
    void changeQ( const QString& text );
    void changeG( const QString& text );
    void changeKeyValue( const QString& text );
private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
};

#endif // GEN_EC_PRI_KEY_DLG_H
