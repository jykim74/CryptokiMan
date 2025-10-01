#ifndef SIGNTHREAD_H
#define SIGNTHREAD_H

#include <QThread>

class SignThread : public QThread
{
    Q_OBJECT

public:
    SignThread();
    ~SignThread();

    void setSession( long uSession );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( qint64 nUpdate );

protected:
    void run() override;
    long session_;
    QString src_file_;
};

#endif // SIGNTHREAD_H
