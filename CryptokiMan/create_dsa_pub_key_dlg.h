#ifndef GEN_DSA_PUB_KEY_DLG_H
#define GEN_DSA_PUB_KEY_DLG_H

#include <QDialog>
#include "ui_create_dsa_pub_key_dlg.h"

namespace Ui {
class CreateDSAPubKeyDlg;
}

class CreateDSAPubKeyDlg : public QDialog, public Ui::CreateDSAPubKeyDlg
{
    Q_OBJECT

public:
    explicit CreateDSAPubKeyDlg(QWidget *parent = nullptr);
    ~CreateDSAPubKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickPrivate();
    void clickEncrypt();
    void clickWrap();
    void clickVerify();
    void clickDerive();
    void clickModifiable();
    void clickToken();
    void clickStartDate();
    void clickEndDate();

    void changeP( const QString& text );
    void changeQ( const QString& text );
    void changeG( const QString& text );
    void changePublic( const QString& text );

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
};

#endif // GEN_EC_PUB_KEY_DLG_H