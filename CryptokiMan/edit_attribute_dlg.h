/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef EDIT_ATTRIBUTE_DLG_H
#define EDIT_ATTRIBUTE_DLG_H

#include <QDialog>
#include "slot_info.h"
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
    int getSlotIndex() { return slot_index_; };

    void setObjectType( int type );
    void setObjectID( long id );
    void setAttrName( const QString& strName );
    bool isChanged() { return is_changed_; };

private slots:
    virtual void accept();
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);

    void labelChanged( int index );
    void objectTypeChanged( int type );
    void attributeTypeChanged( int index );

    void clickClose();
    void clickGetAttribute();
    void clickSetAttribute();

    void changeValue();
    void clickObjectView();

private:
    void initialize();
    void initAttributes();

    int object_type_;
    long object_id_;
    SlotInfo slot_info_;
    int slot_index_ = -1;

    QString attr_name_;
    bool is_changed_ = false;
};

#endif // EDIT_ATTRIBUTE_DLG_H
