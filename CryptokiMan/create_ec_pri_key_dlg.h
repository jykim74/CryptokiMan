#ifndef GEN_EC_PRI_KEY_DLG_H
#define GEN_EC_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_create_ec_pri_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class CreateECPriKeyDlg;
}

class CreateECPriKeyDlg : public QDialog, public Ui::CreateECPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreateECPriKeyDlg(QWidget *parent = nullptr);
    ~CreateECPriKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickGenKey();
    void clickUseSKI();
    void clickPrivate();
    void clickDecrypt();
    void clickSign();
    void clickSignRecover();
    void clickUnwrap();
    void clickModifiable();
    void clickSensitive();
    void clickDerive();
    void clickExtractable();
    void clickToken();
    void clickStartDate();
    void clickEndDate();

    void changeECParams( const QString& text );
    void changeKeyValue( const QString& text );
private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
    int getSKI( BIN *pSKI );
};

#endif // GEN_EC_PRI_KEY_DLG_H
