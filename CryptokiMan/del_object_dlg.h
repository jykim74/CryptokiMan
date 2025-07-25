/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DEL_OBJECT_DLG_H
#define DEL_OBJECT_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_del_object_dlg.h"

namespace Ui {
class DelObjectDlg;
}

class DelObjectDlg : public QDialog, public Ui::DelObjectDlg
{
    Q_OBJECT

public:
    explicit DelObjectDlg(QWidget *parent = nullptr);
    ~DelObjectDlg();
    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setObjectType( int type );
    void setObjectID( long id );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);

    void deleteObj();
    void deleteAllObj();
    void viewObj();

    void labelChanged( int index );
    void objectTypeChanged( int type );


private:
    void initialize();

    int object_type_;
    long object_id_;

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // DEL_OBJECT_DLG_H
