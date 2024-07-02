#ifndef VERIFYTHREAD_H
#define VERIFYTHREAD_H

#include <QThread>

class VerifyThread : public QThread
{
    Q_OBJECT
public:
    VerifyThread();
    ~VerifyThread();

    void setSession( long uSession );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;
    long session_;
    QString src_file_;
};

#endif // VERIFYTHREAD_H
