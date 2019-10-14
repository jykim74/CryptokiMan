#ifndef LOG_VIEW_DLG_H
#define LOG_VIEW_DLG_H

#include <QDialog>

namespace Ui {
class LogViewDlg;
}

class LogViewDlg : public QDialog
{
    Q_OBJECT

public:
    explicit LogViewDlg(QWidget *parent = nullptr);
    ~LogViewDlg();

private:
    Ui::LogViewDlg *ui;
};

#endif // LOG_VIEW_DLG_H
