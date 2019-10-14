#ifndef LOG_VIEW_DLG_H
#define LOG_VIEW_DLG_H

#include <QDialog>
#include "ui_log_view_dlg.h"

namespace Ui {
class LogViewDlg;
}

class LogViewDlg : public QDialog, public Ui::LogViewDlg
{
    Q_OBJECT

public:
    explicit LogViewDlg(QWidget *parent = nullptr);
    ~LogViewDlg();

private:

};

#endif // LOG_VIEW_DLG_H
