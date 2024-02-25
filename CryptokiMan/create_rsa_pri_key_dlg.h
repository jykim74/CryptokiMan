/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_RSA_PRI_KEY_DLG_H
#define GEN_RSA_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_create_rsa_pri_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class CreateRSAPriKeyDlg;
}

class CreateRSAPriKeyDlg : public QDialog, public Ui::CreateRSAPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreateRSAPriKeyDlg(QWidget *parent = nullptr);
    ~CreateRSAPriKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickGenKey();
    void clickFindKey();

    void clickUseSKI();
    void clickUseSPKI();

    void clickPrivate();
    void clickDecrypt();
    void clickSign();
    void clickSignRecover();
    void clickUnwrap();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickSensitive();
    void clickDerive();
    void clickExtractable();
    void clickToken();
    void clickStartDate();
    void clickEndDate();

    void changeModules( const QString& text );
    void changePubExponent( const QString& text );
    void changePriExponent( const QString& text );
    void changePrime1( const QString& text );
    void changePrime2( const QString& text );
    void changeExponent1( const QString& text );
    void changeExponent2( const QString& text );
    void changeCoefficient( const QString& text );

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
    int getSKI_SPKI( BIN *pSKI, BIN *pSPKI );
};

#endif // GEN_RSA_PRI_KEY_DLG_H
