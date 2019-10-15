#ifndef SETTINGS_DLG_H
#define SETTINGS_DLG_H

#include <QDialog>
#include "ui_settings_dlg.h"

namespace Ui {
class SettingsDlg;
}

class SettingsDlg : public QDialog, public Ui::SettingsDlg
{
    Q_OBJECT

public:
    explicit SettingsDlg(QWidget *parent = nullptr);
    ~SettingsDlg();

private:

};

#endif // SETTINGS_DLG_H
