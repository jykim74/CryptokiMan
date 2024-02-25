/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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

    void setSlotIndex( int index );
    void setObjectType( int type );
    void setObjectID( long id );
    void setAttrName( const QString& strName );

private slots:
    virtual void accept();
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);

    void slotChanged( int index );
    void labelChanged( int index );
    void objectTypeChanged( int type );

    void clickClose();
    void clickGetAttribute();
    void clickSetAttribute();

    void changeValue();

private:
    void initialize();
    void initAttributes();

    int slot_index_;
    int object_type_;
    long object_id_;
    long session_;
    QString attr_name_;
};

#endif // EDIT_ATTRIBUTE_DLG_H
